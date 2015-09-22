package goauth

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/dchest/uniuri"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"golang.org/x/oauth2"
)

var (
	ErrJsonFmt      = errors.New("Json format error")
	ErrNoKid        = errors.New("Kid not found")
	ErrLinkSelf     = errors.New("There is already a same account that belongs to you")
	ErrInvalideUser = errors.New("User is invalide")
)

type GetAuthedUserJson func(tok *oauth2.Token) (*simplejson.Json, error)

type OauthUser interface {
	GetOid() (provider, oid string)
	OnLogin(provider, oid, name, pic string) error
	OnLink(existed interface{}, provider, oid, name, pic string) error
	Find(provider, oid string) error
	Info() interface{}
	Valid() bool
}

type Unlinkable interface {
	Unlink(prd string) error
}

type Logoffable interface {
	Logoff() error
}

// priority: GetAuthedUserJson > Endpoint
type Provider struct {
	oauth2.Config
	Name              string
	UserEndpoint      string
	JsonPathOid       string
	JsonPathName      string
	JsonPathPic       string
	GetAuthedUserJson GetAuthedUserJson
}

type Config struct {
	Providers    map[string]Provider
	GinClaimsKey string
	GinUserKey   string
	NewUserFunc  func() OauthUser

	SignAlg       string
	TokenLife     time.Duration
	FindSignKey   func() (string, interface{})
	FindVerifyKey jwt.Keyfunc
}

func (config *Config) loadDefault() {
	if config.NewUserFunc == nil {
		panic("NewUserFunc must be set")
	}
	if config.GinClaimsKey == "" {
		config.GinClaimsKey = "claims"
	}
	if config.GinUserKey == "" {
		config.GinUserKey = "user"
	}
	if config.SignAlg == "" {
		config.SignAlg = "HS256"
	}
	if config.TokenLife == 0 {
		config.TokenLife = time.Minute * 30
	}
	if config.FindSignKey == nil && config.FindVerifyKey == nil {
		tmpKey := []byte(uniuri.NewLen(32))
		config.FindSignKey = func() (string, interface{}) { return "kid", tmpKey }
		config.FindVerifyKey = func(*jwt.Token) (interface{}, error) { return tmpKey, nil }
	}
}

func (config *Config) DefaultGetAuthedUserJson(provider *Provider) GetAuthedUserJson {
	return func(tok *oauth2.Token) (*simplejson.Json, error) {
		// 1. Send request with access_token if needed
		endpoint := provider.UserEndpoint
		if strings.Contains(endpoint, "$(access_token)") {
			// add this for some broken vendors
			endpoint = strings.Replace(endpoint, "$(access_token)", tok.AccessToken, -1)
		}
		r, err := provider.Client(oauth2.NoContext, tok).Get(endpoint)
		if err != nil {
			return nil, err
		}
		// 2. Extract json obj
		raw, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		glog.Infof("Userinfo:%s\n", raw)
		// escape jsonp callback
		index := bytes.IndexAny(raw, "{(")
		if index == -1 {
			return nil, ErrJsonFmt
		}
		if raw[index] == '(' {
			last := bytes.LastIndex(raw, []byte{')'})
			if last == -1 || last < index {
				return nil, ErrJsonFmt
			}
			raw = raw[index+1 : last]
		}
		return simplejson.NewJson(raw)
	}
}

func jsGetPath(js *simplejson.Json, path string) *simplejson.Json {
	return js.GetPath(strings.Split(path, ".")...)
}

func (config *Config) getAuthedUser(provider *Provider, c *gin.Context, tok *oauth2.Token) (OauthUser, error) {
	// 1. Get user json obj
	if provider.GetAuthedUserJson == nil {
		provider.GetAuthedUserJson = config.DefaultGetAuthedUserJson(provider)
	}
	js, err := provider.GetAuthedUserJson(tok)
	if err != nil {
		return nil, err
	}
	// 2. Get oid,name,pic
	ioid := jsGetPath(js, provider.JsonPathOid).Interface()
	var oid string
	switch id := ioid.(type) {
	case string:
		oid = id
	case float64:
		oid = strconv.FormatInt(int64(id), 36)
	default:
		return nil, ErrJsonFmt
	}
	name, _ := jsGetPath(js, provider.JsonPathName).String()
	pic, _ := jsGetPath(js, provider.JsonPathPic).String()
	if name == "" {
		name = provider.Name + " User"
	}
	expected := config.NewUserFunc()
	// 3. Link to exist user if already authed
	if u, ok := c.Get(config.GinUserKey); ok {
		existed := u.(OauthUser)
		if prd, eid := existed.GetOid(); prd == provider.Name && eid == oid {
			return nil, ErrLinkSelf
		}
		return expected, expected.OnLink(existed, provider.Name, oid, name, pic)
	}
	// 4. Create a new user or return an existing one
	return expected, expected.OnLogin(provider.Name, oid, name, pic)
}

func (config *Config) authHandle(c *gin.Context) error {
	raw, _ := ioutil.ReadAll(c.Request.Body)
	js, err := simplejson.NewJson(raw)
	glog.Infof("Code Body:%s\n", raw)
	if err != nil {
		return err
	}
	code, err := js.Get("code").String()
	if err != nil {
		return err
	}
	// continue auth
	provider := config.Providers[c.Request.URL.Path]
	tok, err := provider.Exchange(oauth2.NoContext, code)
	if err != nil {
		return err
	}
	user, err := config.getAuthedUser(&provider, c, tok)
	if err != nil {
		return err
	}
	if !user.Valid() {
		return ErrInvalideUser
	}

	token, err := config.NewToken(user)
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, token)
	return nil
}

func Middleware(config *Config) gin.HandlerFunc {
	if config == nil {
		panic("goauth config is nil")
	}
	config.loadDefault()

	return func(c *gin.Context) {
		token, err := jwt.ParseFromRequest(c.Request, config.FindVerifyKey)
		if err == nil && token.Valid {
			c.Set(config.GinClaimsKey, token.Claims)
		}

		if _, ok := config.Providers[c.Request.URL.Path]; ok && c.Request.Method == "POST" {
			config.BindUser(c)
			if _, ok := c.Get("invalide-user"); ok {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			if err := config.authHandle(c); err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
			}
		}
	}
}

// Temp tolerate panic
func (config *Config) Unlink(c *gin.Context) {
	js, err := simplejson.NewFromReader(c.Request.Body)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	prd, err := js.Get("provider").String()
	if err != nil || prd == "" {
		c.AbortWithError(http.StatusExpectationFailed, err)
		return
	}
	if err := c.Keys[config.GinUserKey].(Unlinkable).Unlink(prd); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.AbortWithStatus(http.StatusOK)
}

func (config *Config) Logoff(c *gin.Context) {
	u, ok := c.Get(config.GinUserKey)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if err := u.(Logoffable).Logoff(); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.AbortWithStatus(http.StatusOK)
}

func (config *Config) NewToken(u OauthUser) (gin.H, error) {
	prd, oid := u.GetOid()
	kid, signKey := config.FindSignKey()
	token := jwt.New(jwt.GetSigningMethod(config.SignAlg))
	token.Header["kid"] = kid
	token.Claims["prd"] = prd
	token.Claims["oid"] = oid
	token.Claims["exp"] = time.Now().Add(config.TokenLife).Unix()
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		glog.Infoln("Sign token err:", err)
		return nil, err
	}
	return gin.H{"token": tokenString, "user": u.Info()}, nil
}

func (config *Config) BindUser(c *gin.Context) {
	obj, ok := c.Get(config.GinClaimsKey)
	if !ok {
		return
	}
	claims, ok := obj.(map[string]interface{})
	if !ok {
		return
	}
	prd, ok1 := claims["prd"].(string)
	oid, ok2 := claims["oid"].(string)
	if !ok1 || !ok2 {
		return
	}
	u := config.NewUserFunc()
	if err := u.Find(prd, oid); err != nil {
		return
	}
	if !u.Valid() {
		c.Set("invalide-user", u)
		return
	}
	c.Set(config.GinUserKey, u)
}

func (config *Config) MustBindUser(c *gin.Context) {
	obj, ok := c.Get(config.GinClaimsKey)
	if !ok {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	claims, ok := obj.(map[string]interface{})
	if !ok {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	prd, ok1 := claims["prd"].(string)
	oid, ok2 := claims["oid"].(string)
	if !ok1 || !ok2 {
		c.AbortWithStatus(http.StatusExpectationFailed)
		return
	}
	u := config.NewUserFunc()
	if err := u.Find(prd, oid); err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	if !u.Valid() {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Set(config.GinUserKey, u)
}
