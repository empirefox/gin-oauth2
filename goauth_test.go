package goauth

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

func init() {
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
}

type user struct {
	Provider string `json:",omitempty"`
	Oid      string `json:",omitempty"`
	V        bool   `json:",omitempty"`
}

func (u *user) GetOid() (provider, oid string) {
	return u.Provider, u.Oid
}

func (u *user) OnLogin(provider, oid, name, pic string) error {
	u.Provider = provider
	u.Oid = oid
	u.V = true
	return nil
}

func (u *user) OnLink(existed interface{}, provider, oid, name, pic string) error {
	*existed.(*user) = user{Provider: provider, Oid: oid, V: true}
	return nil
}

func (u *user) Find(provider, oid string) error {
	u.Provider = provider
	u.Oid = oid
	u.V = true
	return nil
}

func (u user) Valid() bool {
	return u.V
}

func (u user) Info() interface{} {
	return u
}

func factoryFunc() OauthUser {
	return &user{V: false}
}

func newConf(url string) *Config {
	glog.Infoln("from server:", url)
	ProviderPresets["github2"] = ProviderPreset{
		TokenURL:     url + "/token",
		UserEndpoint: url + "/user",
		JsonPathOid:  "oid",
	}
	config := &Config{
		Origin:      url,
		NewUserFunc: factoryFunc,
		SignAlg:     "HS256",
		FindSignKey: func() (string, interface{}) {
			return "kid", []byte("hmac-sercet")
		},
		FindVerifyKey: func(token *jwt.Token) (interface{}, error) {
			return []byte("hmac-sercet"), nil
		},
	}
	config.loadDefault()
	if err := config.AddProvider("github2", "/auth/github2", "CLIENT_ID", "CLIENT_SECRET"); err != nil {
		glog.Fatalln(err)
	}
	return config
}

func requestAndResponse(serverUrl, method, path string, payload io.Reader) *httptest.ResponseRecorder {
	conf := newConf(serverUrl)
	r := gin.Default()
	r.Use(Middleware(conf))
	res := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, payload)
	r.ServeHTTP(res, req)
	return res
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
	res := requestAndResponse(ts.URL, "POST", "/auth/github2", strings.NewReader(`{"code":"exchange-code"}`))
	if res.Code != http.StatusOK {
		t.Errorf("Response code=%d, expectd:%d", res.Code, http.StatusOK)
	}
	info, _ := json.Marshal(user{Provider: "github2", Oid: "OAUTH_ID", V: true})
	gotInfo := res.Body.Bytes()
	if !bytes.Contains(gotInfo, info) {
		t.Errorf("Response should contains right user info, but got:%s", gotInfo)
	}
}

func TestMiddleware(t *testing.T) {
	conf := newConf("")
	r := gin.Default()
	r.Use(Middleware(conf))
	var u *user
	r.GET("/secure", conf.MustBindUser, func(c *gin.Context) {
		u = c.Keys[conf.GinUserKey].(*user)
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/secure", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvaWQiOiJPQVVUSF9JRCIsInByZCI6ImdpdGh1YjIifQ.c33cisU8gp_i2G2U7oUI0pRxFRLRkxy0667VjkX2mi4")
	r.ServeHTTP(res, req)
	if res.Code == http.StatusOK {
		t.Errorf("Non-authed request should be rejected, but got:%d", res.Code)
	}
	if u != nil {
		t.Errorf("Non-authed request should be rejected")
	}

	res = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/secure", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvaWQiOiJPQVVUSF9JRCIsInByZCI6ImdpdGh1YiJ9.c33cisU8gp_i2G2U7oUI0pRxFRLRkxy0667VjkX2mi4")
	r.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("Authed request should be accepted, but got:%d", res.Code)
	}
	if u == nil {
		t.Errorf("Authed request should be accepted")
	}
	if u.Provider != "github2" || u.Oid != "OAUTH_ID" {
		t.Errorf("Claims should contain correct info, but got:%v", u)
	}
}
