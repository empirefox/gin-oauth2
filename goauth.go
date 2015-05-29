package goauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	NoCheck = iota - 1
	Loggedin
	Permitted
)

var (
	JsonFormatErr = errors.New("Json format error")
)

type GetAuthenticatedUser func(client *http.Client) (OauthUser, error)

type OauthUser interface {
	OnOid(provider, oid string) error
	Permitted(c *gin.Context) bool
	Valid() bool
}

// priority: GetAuthenticatedUser > Endpoint
type Provider struct {
	oauth2.Config
	Name                 string
	UserEndpoint         string
	OidJsonPath          string
	GetAuthenticatedUser GetAuthenticatedUser
}

type Config struct {
	StoreGinKey       string
	SessionName       string
	SessionSerialName string
	CookieAuthKey     []byte
	CookieEncryptKey  []byte
	CookieOptions     sessions.Options
	PathLogin         string
	PathLogout        string
	PathSuccess       string
	PathNotPermitted  string
	OriginUrlKey      string
	Providers         map[string]Provider
	UserGinKey        string
	NewUserFunc       func() OauthUser

	// priority: FakeUser > FakeLogin > normal
	FakeUser  OauthUser
	FakeLogin gin.HandlerFunc

	// Will ignore the dependent items when giving Store manual
	Store *sessions.CookieStore
}

func (config *Config) loadDefault() {
	if config.StoreGinKey == "" {
		config.StoreGinKey = "gorilla-sessions-store"
	}
	if config.SessionName == "" {
		config.SessionName = "_g_sess"
	}
	if config.SessionSerialName == "" {
		config.SessionSerialName = "gorilla-session"
	}
	if config.CookieAuthKey == nil {
		config.CookieAuthKey = securecookie.GenerateRandomKey(64)
	}
	if config.CookieEncryptKey == nil {
		config.CookieEncryptKey = securecookie.GenerateRandomKey(32)
	}
	if config.CookieOptions.Path == "" {
		config.CookieOptions.Path = "/"
	}
	if config.CookieOptions.MaxAge == 0 {
		config.CookieOptions.MaxAge = 86400 * 30
	}

	if config.PathLogin == "" {
		config.PathLogin = "/login.html"
	}
	if config.PathLogout == "" {
		config.PathLogout = "/logout"
	}
	if config.PathSuccess == "" {
		config.PathSuccess = "/"
	}
	if config.PathNotPermitted == "" {
		config.PathNotPermitted = "/403.html"
	}
	if config.OriginUrlKey == "" {
		config.OriginUrlKey = "from"
	}
	if config.UserGinKey == "" {
		config.UserGinKey = "user"
	}

	// Will igore params if Store exist.
	// Useful for test
	if config.Store == nil {
		config.Store = &sessions.CookieStore{
			Codecs:  securecookie.CodecsFromPairs(config.CookieAuthKey, config.CookieEncryptKey),
			Options: &config.CookieOptions,
		}
	}
}

func (config *Config) DefaultGetAuthenticatedUser(provider *Provider) GetAuthenticatedUser {
	return func(client *http.Client) (OauthUser, error) {
		r, err := client.Get(provider.UserEndpoint)
		if err != nil {
			glog.Infoln(err)
			return nil, err
		}
		raw, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			glog.Errorln(err)
			return nil, err
		}
		// escape jsonp callback
		index := bytes.IndexAny(raw, "{(")
		if index == -1 {
			glog.Errorln(JsonFormatErr)
			return nil, JsonFormatErr
		}
		if raw[index] == '(' {
			last := bytes.LastIndex(raw, []byte{')'})
			if last == -1 || last < index {
				glog.Errorln(JsonFormatErr)
				return nil, JsonFormatErr
			}
			raw = raw[index+1 : last]
		}
		js, err := simplejson.NewJson(raw)
		if err != nil {
			glog.Errorln(err)
			return nil, err
		}
		oid, err := js.GetPath(strings.Split(provider.OidJsonPath, ".")...).String()
		if err != nil {
			glog.Errorln(err)
			return nil, err
		}
		u := config.NewUserFunc()
		if err = u.OnOid(provider.Name, oid); err != nil {
			glog.Errorln(err)
			return nil, err
		}
		return u, nil
	}
}

func (config *Config) getOriginUrl(successRawUrl, path string) (successUrlStr string) {
	successUrl, err := url.Parse(successRawUrl)
	if err != nil || successUrl.Path == config.PathLogin || successUrl.Path == config.PathLogout {
		return
	}
	if _, ok := config.Providers[path]; ok {
		return
	}
	if successUrl.IsAbs() {
		successUrl.Scheme = ""
		successUrl.Host = ""
		successUrlStr = successUrl.String()
		return
	}
	successUrlStr = successRawUrl
	return
}

func (config *Config) authHandle(c *gin.Context) bool {
	requrl := c.Request.URL
	if provider, ok := config.Providers[requrl.Path]; ok {
		if c.Request.Method != "GET" {
			c.String(http.StatusMethodNotAllowed, "Only accept get method")
			return true
		}
		// do auth process and return
		vs := requrl.Query()
		code := vs.Get("code")
		if code == "" {
			successUrl := config.getOriginUrl(vs.Get(config.OriginUrlKey), requrl.Path)
			// no code, just redirect user to provider
			c.Redirect(http.StatusSeeOther, provider.AuthCodeURL(successUrl))
			return true
		}

		tok, err := provider.Exchange(oauth2.NoContext, code)
		if err != nil {
			c.String(http.StatusNonAuthoritativeInfo, "Auth proccess failed")
			return true
		}
		client := provider.Client(oauth2.NoContext, tok)
		if provider.GetAuthenticatedUser == nil {
			provider.GetAuthenticatedUser = config.DefaultGetAuthenticatedUser(&provider)
		}
		user, err := provider.GetAuthenticatedUser(client)
		if err != nil {
			c.String(http.StatusNonAuthoritativeInfo, "Get auth user failed")
			return true
		}
		session, err := config.Store.Get(c.Request, config.SessionName)
		if err != nil {
			glog.Infoln("Auth session decode error, or create new session")
		}
		serial, err := json.Marshal(user)
		if err != nil {
			c.String(http.StatusInternalServerError, "When Marshal user")
			return true
		}
		session.Values[config.SessionSerialName] = serial
		if err = session.Save(c.Request, c.Writer); err != nil {
			c.String(http.StatusInternalServerError, "Cannot save session")
			return true
		}
		// redirect to prev url
		success := vs.Get("state")
		if success == "" {
			success = config.PathSuccess
		}
		c.Redirect(http.StatusSeeOther, success)
		return true
	}
	// not handled
	return false
}

func Setup(config *Config) gin.HandlerFunc {
	if config == nil {
		panic("goauth config is nil")
	}
	config.loadDefault()

	if config.FakeUser != nil || config.FakeLogin != nil {
		return config.fakeOauth()
	}

	return func(c *gin.Context) {
		defer context.Clear(c.Request)
		c.Set(config.StoreGinKey, config.Store)

		if config.authHandle(c) {
			return
		}

		session, err := config.Store.Get(c.Request, config.SessionName)
		if err != nil {
			glog.Infoln("Session decode error")
		}

		if serial, ok := session.Values[config.SessionSerialName]; ok {
			user := config.NewUserFunc()
			if err := json.Unmarshal(serial.([]byte), user); err == nil {
				c.Set(config.UserGinKey, user)
			} else {
				glog.Infoln(err)
			}
		}

		c.Next()
	}
}

// Levels: NoCheck, Loggedin, Permitted
func (config *Config) Check(level int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if level == NoCheck {
			return
		}
		iuser, err := c.Get(config.UserGinKey)
		if err != nil {
			c.Redirect(http.StatusSeeOther, config.PathLogin)
			c.Abort()
			return
		}
		user, ok := iuser.(OauthUser)
		if !ok {
			c.String(http.StatusInternalServerError, "")
			c.Abort()
			return
		}
		if level >= Loggedin && !user.Valid() {
			c.Redirect(http.StatusSeeOther, config.PathLogin)
			c.Abort()
			return
		}
		if level >= Permitted && !user.Permitted(c) {
			c.Redirect(http.StatusSeeOther, config.PathNotPermitted)
			c.Abort()
			return
		}
	}
}

func (config *Config) DeleteUserCookie(c *gin.Context) {
	if _, ok := c.Keys[config.UserGinKey]; ok {
		delete(c.Keys, config.UserGinKey)
	}
	session, err := config.Store.Get(c.Request, config.SessionName)
	if err != nil {
		glog.Infoln("Session decode error")
		return
	}
	for key, _ := range session.Values {
		delete(session.Values, key)
	}
	if err = session.Save(c.Request, c.Writer); err != nil {
		c.String(http.StatusInternalServerError, "Cannot change session")
		return
	}
}

// Logout delete user cookie and redirect to login page
func (config *Config) DefaultLogout(c *gin.Context) {
	config.DeleteUserCookie(c)
	c.Redirect(http.StatusSeeOther, config.PathLogin)
}

// Only works when FakeUser/FakeLogin exist, and will ignore normal login
func (config *Config) fakeOauth() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer context.Clear(c.Request)
		c.Set(config.StoreGinKey, config.Store)

		if _, ok := config.Providers[c.Request.URL.Path]; ok {
			glog.Errorln("No Fake Login Expected")
			c.Redirect(http.StatusSeeOther, config.PathSuccess)
			return
		}

		if config.FakeUser != nil {
			c.Set(config.UserGinKey, config.FakeUser)
		} else if config.FakeLogin != nil {
			config.FakeLogin(c)
		}

		c.Next()
	}
}
