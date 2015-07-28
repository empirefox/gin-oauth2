package goauth

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/dchest/uniuri"
	"github.com/empirefox/gotool/web"
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

func init() {
	gob.Register(&LoginFlash{})
}

type LoginFlash struct {
	Url   string
	State string
}

type GetAuthenticatedUser func(tok *oauth2.Token) (OauthUser, error)

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

// PathLoginFail accept var: status
type Config struct {
	StoreGinKey       string
	SessionName       string
	SessionSerialName string
	SessionFlashKey   string
	CookieAuthKey     []byte
	CookieEncryptKey  []byte
	CookieOptions     sessions.Options
	ClientSessionName string
	PathLogin         string
	PathLoginFail     string
	PathLoginFailVar  string
	PathLogout        string
	PathSuccess       string
	PathNotPermitted  string
	Path500           string
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
	if config.SessionFlashKey == "" {
		config.SessionFlashKey = "_login_flash"
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
	if config.ClientSessionName == "" {
		config.ClientSessionName = "MC_OK"
	}

	if config.PathLogin == "" {
		config.PathLogin = "/login.html"
	}
	if config.PathLoginFail == "" {
		config.PathLoginFail = "/login.html"
	}
	if config.PathLoginFailVar == "" {
		config.PathLoginFailVar = "err"
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
	return func(tok *oauth2.Token) (OauthUser, error) {
		endpoint := provider.UserEndpoint
		if strings.Contains(endpoint, "$(access_token)") {
			// if not so, some vendor may not get token
			endpoint = strings.Replace(endpoint, "$(access_token)", tok.AccessToken, -1)
		}
		r, err := provider.Client(oauth2.NoContext, tok).Get(endpoint)
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
		glog.Infoln(string(raw))
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

func (config *Config) getOriginUrl(vs url.Values) (success string) {
	raw, err := url.QueryUnescape(vs.Get(config.OriginUrlKey))
	if err != nil {
		return
	}
	successUrl, err := url.Parse(raw)
	if err != nil || successUrl.Path == config.PathLogin || successUrl.Path == config.PathLogout {
		return
	}
	if _, ok := config.Providers[successUrl.Path]; ok {
		return
	}
	success = raw
	return
}

func (config *Config) setClientSession(c *gin.Context, authed string) {
	http.SetCookie(c.Writer, &http.Cookie{Name: config.ClientSessionName, Value: authed})
}

// status 0: no error
func (config *Config) authHandle(c *gin.Context) (handled bool, status int) {
	requrl := c.Request.URL
	provider, ok := config.Providers[requrl.Path]
	if !ok {
		return // not handled
	}
	handled = true

	if c.Request.Method != "GET" {
		glog.Infoln("Only accept get method")
		return handled, http.StatusMethodNotAllowed
	}
	// do auth process and return
	session, err := config.Store.Get(c.Request, config.SessionName)
	if err != nil {
		glog.Infoln("Auth session decode error, or create new session")
	}
	flashs := session.Flashes(config.SessionFlashKey)

	vs := requrl.Query()
	code := vs.Get("code")
	if code == "" {
		fmsg := &LoginFlash{Url: config.getOriginUrl(vs), State: uniuri.NewLen(8)}
		session.AddFlash(fmsg, config.SessionFlashKey)
		if err := session.Save(c.Request, c.Writer); err != nil {
			glog.Infoln("Cannot save flash session:", err)
			return handled, http.StatusInternalServerError
		}
		config.setClientSession(c, "1")

		c.Redirect(http.StatusSeeOther, provider.AuthCodeURL(fmsg.State))
		return handled, status
	}

	// validate state
	if len(flashs) == 0 {
		glog.Infoln("Flash not found")
		return handled, http.StatusInternalServerError
	}
	fmsg, ok := flashs[0].(*LoginFlash)
	if !ok {
		glog.Infoln("Flash assert error")
		return handled, http.StatusInternalServerError
	}
	if vs.Get("state") != fmsg.State {
		glog.Infoln("State in flash not matched")
		return handled, http.StatusBadGateway
	}

	// continue auth
	tok, err := provider.Exchange(oauth2.NoContext, code)
	if err != nil {
		glog.Infoln("Auth exchange proccess failed, code:", code, "err:", err)
		return handled, http.StatusNonAuthoritativeInfo
	}
	if provider.GetAuthenticatedUser == nil {
		provider.GetAuthenticatedUser = config.DefaultGetAuthenticatedUser(&provider)
	}
	user, err := provider.GetAuthenticatedUser(tok)
	if err != nil {
		glog.Infoln("Get auth user failed, token:", tok, "err:", err)
		return handled, http.StatusNonAuthoritativeInfo
	}
	serial, err := json.Marshal(user)
	if err != nil {
		glog.Infoln("Marshal user err:", err, "user:", user)
		return handled, http.StatusInternalServerError
	}
	session.Values[config.SessionSerialName] = serial
	if err = session.Save(c.Request, c.Writer); err != nil {
		glog.Infoln("Cannot save user to session:", err)
		return handled, http.StatusInternalServerError
	}
	config.setClientSession(c, "1")

	// redirect to prev url
	if fmsg.Url == "" {
		fmsg.Url = config.PathSuccess
	}
	c.Redirect(http.StatusSeeOther, fmsg.Url)
	return handled, 0
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

		if handled, status := config.authHandle(c); handled {
			if status != 0 {
				if web.AcceptJson(c.Request) {
					c.JSON(status, "")
				} else {
					// inject status to failed page
					c.Redirect(http.StatusSeeOther, os.Expand(config.PathLoginFail, func(s string) string {
						if s == config.PathLoginFailVar {
							return strconv.Itoa(status)
						}
						return ""
					}))
				}
			}
			c.Abort()
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

func (config *Config) CheckStatus(c *gin.Context, level int) (bool, int) {
	if level == NoCheck {
		return true, 0
	}
	iuser, ok := c.Get(config.UserGinKey)
	if !ok {
		glog.Infoln("user not found")
		for _, cookie := range c.Request.Cookies() {
			glog.Infoln(*cookie)
		}
		return false, http.StatusUnauthorized
	}
	user, ok := iuser.(OauthUser)
	if !ok {
		glog.Infoln("OauthUser type error")
		return false, http.StatusInternalServerError
	}
	if level >= Loggedin && !user.Valid() {
		return false, http.StatusUnauthorized
	}
	if level >= Permitted && !user.Permitted(c) {
		return false, http.StatusForbidden
	}
	return true, 0
}

func (config *Config) GetLoginHref(c *gin.Context) string {
	return fmt.Sprintf(`%s?%s=%s`,
		config.PathLogin,
		config.OriginUrlKey,
		url.QueryEscape(c.Request.URL.String()))
}

// Levels: NoCheck, Loggedin, Permitted
func (config *Config) Check(level int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ok, status := config.CheckStatus(c, level)
		if ok {
			return
		}
		switch status {
		case http.StatusInternalServerError:
			if web.AcceptJson(c.Request) {
				c.JSON(http.StatusInternalServerError, "")
			} else if config.Path500 != "" {
				c.Redirect(http.StatusSeeOther, config.Path500)
			} else {
				panic("")
			}
		case http.StatusUnauthorized:
			c.Redirect(http.StatusSeeOther, config.GetLoginHref(c))
		case http.StatusForbidden:
			c.Redirect(http.StatusSeeOther, config.PathNotPermitted)
		}
		c.Abort()
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
	config.setClientSession(c, "")
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
