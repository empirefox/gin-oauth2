package goauth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
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
	ErrJsonFmt       = errors.New("Json format error")
	ErrNoKid         = errors.New("Kid not found")
	ErrLinkSelf      = errors.New("There is already a same account that belongs to you")
	ErrFindUser      = errors.New("Cannot find user")
	ErrInvalideUser  = errors.New("User is invalide")
	ErrInvalideToken = errors.New("Token is invalide")
)

type OauthUser interface {
	GetOid() (provider, oid string)
	OnLogin(provider, oid, name, pic string) error
	OnLink(existed interface{}, provider, oid, name, pic string) error
	Find(provider, oid string) error
	Info() interface{}
	Valid() bool
}

// Config.Unlink require this
type Unlinkable interface {
	Unlink(prd string) error
}

// Config.Logoff require this
type Logoffable interface {
	Logoff() error
}

type Provider struct {
	ProviderPreset
	*oauth2.Config
	Name              string
	GetAuthedUserJson GetAuthedUserJson
}

type Config struct {
	Providers    map[string]Provider
	Origin       string
	GinClaimsKey string
	GinUserKey   string
	NewUserFunc  func() OauthUser

	SignAlg       string
	TokenLife     time.Duration
	FindSignKey   func() (string, interface{})
	FindVerifyKey jwt.Keyfunc

	HandleUserInfoFunc func(c *gin.Context, info *UserInfo) error
}

func (config *Config) loadDefault() {
	if config.NewUserFunc == nil {
		panic("NewUserFunc must be set")
	}
	if config.Providers == nil {
		config.Providers = make(map[string]Provider, 0)
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

func (config *Config) AddProvider(Name, Path, ClientID, ClientSecret string) error {
	preset, ok := ProviderPresets[Name]
	if !ok {
		return errors.New(fmt.Sprintf("Provider %s is not supported!\n", Name))
	}
	if config.Providers == nil {
		config.Providers = make(map[string]Provider, 0)
	}
	oconfig := &oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		RedirectURL:  config.Origin + preset.RedirectEnd,
		Endpoint: oauth2.Endpoint{
			TokenURL: preset.TokenURL,
		},
	}
	config.Providers[Path] = Provider{
		Name:              Name,
		ProviderPreset:    preset,
		Config:            oconfig,
		GetAuthedUserJson: preset.GetUserJsonFactory(oconfig),
	}
	return nil
}

func jsGetPath(js *simplejson.Json, path string) *simplejson.Json {
	return js.GetPath(strings.Split(path, ".")...)
}

func (config *Config) getUserInfo(provider *Provider, code string) (*UserInfo, error) {
	// 1. Get token
	tok, err := provider.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}
	// 2. Get user jsons
	jss, err := provider.GetAuthedUserJson(tok)
	if err != nil {
		return nil, err
	}
	// 3. Get user info
	return provider.ParseUserInfo(tok, jss, provider.Name)
}

func (config *Config) getAuthedUser(c *gin.Context, info *UserInfo) (OauthUser, error) {
	expected := config.NewUserFunc()
	// 3. Link to exist user if already authed
	if u, ok := c.Get(config.GinUserKey); ok {
		existed := u.(OauthUser)
		if prd, eid := existed.GetOid(); prd == info.Provider && eid == info.Oid {
			return nil, ErrLinkSelf
		}
		return expected, expected.OnLink(existed, info.Provider, info.Oid, info.Name, info.Picture)
	}
	// 4. Create a new user or return an existing one
	return expected, expected.OnLogin(info.Provider, info.Oid, info.Name, info.Picture)
}

func (config *Config) HandleUserInfo(c *gin.Context, info *UserInfo) error {
	user, err := config.getAuthedUser(c, info)
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
	if provider.RedirectURL == "" {
		redirectUri, err := js.Get("redirectUri").String()
		if err != nil {
			return err
		}
		provider.RedirectURL = redirectUri
	}
	info, err := config.getUserInfo(&provider, code)
	if err != nil {
		return err
	}
	if config.HandleUserInfoFunc != nil {
		return config.HandleUserInfoFunc(c, info)
	} else {
		return config.HandleUserInfo(c, info)
	}
}

// Middleware proccess Login related logic.
// It does not block the user handler, just try to retrieve Token.Claims.
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

// Unlink will proxy to OauthUser.Unlink.
// OauthUser must implement Unlinkable. Following Config.Middleware when using.
// Temp tolerate panic.
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

// Logoff will proxy to OauthUser.Logoff.
// OauthUser must implement Logoffable. Following Config.Middleware when using.
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

// NewToken generate {token,user} json
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

func (config *Config) retrieveUser(user OauthUser, claims map[string]interface{}) error {
	prd, ok1 := claims["prd"].(string)
	oid, ok2 := claims["oid"].(string)
	if !ok1 || !ok2 {
		return ErrInvalideToken
	}
	if err := user.Find(prd, oid); err != nil {
		return ErrFindUser
	}
	return nil
}

func (config *Config) retrieveClaims(c *gin.Context) (claims map[string]interface{}, ok bool) {
	obj, exist := c.Get(config.GinClaimsKey)
	if !exist {
		return nil, false
	}
	claims, ok = obj.(map[string]interface{})
	return
}

// Verify parse token then query the user, it dose not create a new one.
// Useful when using websocket.
func (config *Config) Verify(user OauthUser, token []byte) error {
	t, err := jwt.Parse(string(token), config.FindVerifyKey)
	if err != nil {
		return err
	}
	if !t.Valid {
		return ErrInvalideToken
	}
	return config.retrieveUser(user, t.Claims)
}

// BindUser silently bind token to user. Combined with Middleware.
func (config *Config) BindUser(c *gin.Context) {
	claims, ok := config.retrieveClaims(c)
	if !ok {
		return
	}
	u := config.NewUserFunc()
	if err := config.retrieveUser(u, claims); err != nil {
		return
	}
	if !u.Valid() {
		c.Set("invalide-user", u)
		return
	}
	c.Set(config.GinUserKey, u)
}

// MustBindUser bind token to user. It will block the next handler when user is invalid.
// Combined with Middleware.
func (config *Config) MustBindUser(c *gin.Context) {
	claims, ok := config.retrieveClaims(c)
	if !ok {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	u := config.NewUserFunc()
	if err := config.retrieveUser(u, claims); err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	if !u.Valid() {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Set(config.GinUserKey, u)
}
