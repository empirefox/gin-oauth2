package goauth

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	. "github.com/smartystreets/goconvey/convey"
)

func init() {
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
}

type user struct {
	P bool `json:",omitempty"`
	V bool `json:",omitempty"`
}

func (u *user) OnOid(provider, oid string) error {
	if oid == "OAUTH_ID" {
		u.P = true
		u.V = true
		return nil
	}
	return errors.New("oid not found")
}

func (u user) Permitted(c *gin.Context) bool {
	return u.P
}

func (u user) Valid() bool {
	return u.V
}

func factoryFunc() OauthUser {
	return &user{P: false, V: false}
}

func newConf(url string) *Config {
	glog.Infoln("from server:", url)
	config := &Config{
		Providers: map[string]Provider{
			"/auth/github": Provider{
				Config: oauth2.Config{
					ClientID:     "CLIENT_ID",
					ClientSecret: "CLIENT_SECRET",
					RedirectURL:  "REDIRECT_URL",
					Scopes:       []string{"scope1"},
					Endpoint: oauth2.Endpoint{
						AuthURL:  url + "/auth",
						TokenURL: url + "/token",
					},
				},
				UserEndpoint: url + "/user",
				OidJsonPath:  "oid",
			},
		},
		NewUserFunc: factoryFunc,
	}
	config.Store = &sessions.CookieStore{
		Codecs:  securecookie.CodecsFromPairs(securecookie.GenerateRandomKey(1)),
		Options: &config.CookieOptions,
	}
	return config
}

func requestAndResponse(serverUrl, method, path string, payload io.Reader) *httptest.ResponseRecorder {
	conf := newConf(serverUrl)
	r := gin.Default()
	r.Use(Setup(conf))
	res := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, payload)
	r.ServeHTTP(res, req)
	return res
}

func requestAndResponseWithFlash(serverUrl, method, path string,
	payload io.Reader,
	flash *LoginFlash) *httptest.ResponseRecorder {

	conf := newConf(serverUrl)
	r := gin.Default()
	r.Use(Setup(conf))
	res := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, payload)

	session, err := conf.Store.Get(req, conf.SessionName)
	if err != nil {
		glog.Errorln(err)
	}
	session.AddFlash(flash, "_login_flash")

	r.ServeHTTP(res, req)
	return res
}

func saveUserToSessionMiddleware(conf *Config, u *user) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := conf.Store.Get(c.Request, conf.SessionName)
		if err != nil {
			glog.Errorln(err)
		}
		serial, err := json.Marshal(u)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		session.Values[conf.SessionSerialName] = serial
	}
}

func TestConfig_authHandle(t *testing.T) {
	Convey("authHandle", t, func() {
		Convey("should reject non-get method", func() {
			res := requestAndResponse("", "POST", "/auth/github", nil)
			So(res.Code, ShouldEqual, http.StatusMethodNotAllowed)
		})
		Convey("should redirect to auth code url", func() {
			res := requestAndResponse("", "GET", "/auth/github", nil)
			So(res.Code, ShouldEqual, http.StatusSeeOther)
			u := res.Header().Get("Location")
			So(u[:len(u)-8], ShouldEqual, "/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1&state=")
		})
	})
}

// Do not use goconvey or it will not pass!
func TestConfig_authHandle_success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"oid": "OAUTH_ID"}`))
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "90d64460d14870c08c81352a05dedd3465940a7c", "scope": "user", "token_type": "bearer", "expires_in": 86400}`))
		}
	}))
	defer ts.Close()
	res := requestAndResponseWithFlash(ts.URL, "GET", "/auth/github?code=exchange-code&state=12345678", nil, &LoginFlash{
		State: "12345678",
	})
	glog.Errorln(string(res.Body.Bytes()))
	if res.Code != http.StatusSeeOther {
		t.Errorf("Response code=%d, expectd:%d", res.Code, http.StatusSeeOther)
	}
	if res.Header().Get("Location") != "/" {
		t.Errorf("Redirect url=(%s), expectd:(%s)", res.Header().Get("Location"), "/")
	}
}

func newRouter(u *user) (*Config, *gin.Engine, *httptest.ResponseRecorder) {
	conf := newConf("")
	r := gin.Default()
	if u != nil {
		r.Use(saveUserToSessionMiddleware(conf, u))
	}
	r.Use(Setup(conf))
	return conf, r, httptest.NewRecorder()
}

func TestSetup(t *testing.T) {
	Convey("Setup", t, func() {
		Convey("should parse user and set to gin context", func() {
			ou := &user{true, false}
			config, r, res := newRouter(ou)
			var u *user
			r.GET("/getuser", func(c *gin.Context) {
				if iuser, err := c.Get(config.UserGinKey); err == nil {
					u = iuser.(*user)
				}
			})
			req, _ := http.NewRequest("GET", "/getuser", nil)
			r.ServeHTTP(res, req)
			So(u, ShouldResemble, ou)
		})
	})
}

func TestConfig_Check(t *testing.T) {
	Convey("Check", t, func() {
		Convey("should accept valid user", func() {
			u := &user{false, true}
			conf, r, res := newRouter(u)
			checked := r.Group("/admin", conf.Check(Loggedin))
			executed := false
			checked.GET("/getuser", func(c *gin.Context) {
				executed = true
				c.String(http.StatusOK, "ok")
			})
			req, _ := http.NewRequest("GET", "/admin/getuser", nil)
			r.ServeHTTP(res, req)
			So(res.Header().Get("Location"), ShouldEqual, "")
			So(res.Code, ShouldEqual, http.StatusOK)
			So(executed, ShouldBeTrue)
		})
		Convey("should reject invalid user", func() {
			u := &user{true, false}
			conf, r, res := newRouter(u)
			checked := r.Group("/admin", conf.Check(Loggedin))
			executed := false
			checked.GET("/getuser", func(c *gin.Context) {
				executed = true
			})
			req, _ := http.NewRequest("GET", "/admin/getuser", nil)
			r.ServeHTTP(res, req)
			So(executed, ShouldBeFalse)
		})
		Convey("should accept permitted user", func() {
			u := &user{true, true}
			conf, r, res := newRouter(u)
			checked := r.Group("/admin", conf.Check(Permitted))
			executed := false
			checked.GET("/getuser", func(c *gin.Context) {
				executed = true
			})
			req, _ := http.NewRequest("GET", "/admin/getuser", nil)
			r.ServeHTTP(res, req)
			So(executed, ShouldBeTrue)
		})
		Convey("should reject non-permitted user", func() {
			u := &user{false, true}
			conf, r, res := newRouter(u)
			checked := r.Group("/admin", conf.Check(Permitted))
			executed := false
			checked.GET("/getuser", func(c *gin.Context) {
				executed = true
			})
			req, _ := http.NewRequest("GET", "/admin/getuser", nil)
			r.ServeHTTP(res, req)
			So(executed, ShouldBeFalse)
		})
	})
}

func TestConfig_DeleteUserCookie(t *testing.T) {
	Convey("DeleteUserCookie", t, func() {
		Convey("should log the user out", func() {
			u := &user{true, true}
			config, r, res := newRouter(u)
			executedBefore := false
			executedAfter := false
			r.GET("/getuser", config.Check(Permitted), func(c *gin.Context) {
				executedBefore = true
			}, config.DefaultLogout, config.Check(Permitted), func(c *gin.Context) {
				executedAfter = true
			})
			req, _ := http.NewRequest("GET", "/getuser", nil)
			r.ServeHTTP(res, req)
			So(executedBefore, ShouldBeTrue)
			So(executedAfter, ShouldBeFalse)
		})
	})
}

func newFakeRequest(fakeUser OauthUser, fakeLogin func(conf *Config) gin.HandlerFunc) *user {
	conf := newConf("")
	conf.FakeUser = fakeUser
	if fakeLogin != nil {
		conf.FakeLogin = fakeLogin(conf)
	}
	r := gin.Default()
	r.Use(Setup(conf))
	var u user
	var got = false
	r.GET("/getuser", func(c *gin.Context) {
		iuser, err := c.Get(conf.UserGinKey)
		if err != nil {
			return
		}
		gu, ok := iuser.(*user)
		if !ok {
			return
		}
		glog.Infoln("got user:", gu)
		u = *gu
		got = true
	})
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/getuser", nil)
	r.ServeHTTP(res, req)
	if got {
		return &u
	}
	return nil
}

func fakeLogin(fakeUser *user) func(conf *Config) gin.HandlerFunc {
	return func(conf *Config) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set(conf.UserGinKey, fakeUser)
		}
	}
}

func TestFakeOauth(t *testing.T) {
	Convey("FakeUser", t, func() {
		Convey("should set user to context", func() {
			fakeUser := &user{true, false}
			u := newFakeRequest(fakeUser, nil)
			So(u, ShouldResemble, fakeUser)
		})
		Convey("should set user to context ignore fakeLogin", func() {
			fakeUser := &user{false, true}
			u := newFakeRequest(fakeUser, fakeLogin(&user{true, true}))
			So(u, ShouldResemble, fakeUser)
		})
	})
	Convey("FakeLogin", t, func() {
		Convey("should set user to context", func() {
			fakeUser := &user{false, true}
			u := newFakeRequest(nil, fakeLogin(fakeUser))
			So(u, ShouldResemble, fakeUser)
		})
	})
}
