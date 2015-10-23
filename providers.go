package goauth

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/bitly/go-simplejson"
	"github.com/golang/glog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
)

type GetAuthedUserJson func(tok *oauth2.Token) (jss []*simplejson.Json, err error)

type userInfo struct {
	Oid     string
	Name    string
	Picture string
}

// default redirect_uri is current page origin
type ProviderPreset struct {
	TokenURL       string
	OpenIdEndpoint string
	UserEndpoint   string
	JsonUserRoot   string
	JsonPathOid    string
	JsonPathName   string
	JsonPathPic    string
	RedirectEnd    string
}

func maybeParseJsonp(raw []byte) (*simplejson.Json, error) {
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

func handleEndpoint(endpoint string, tok *oauth2.Token, client *http.Client, jss ...*simplejson.Json) (*simplejson.Json, error) {
	r, err := client.Get(os.Expand(endpoint, parseMapping(tok, jss)))
	if err != nil {
		return nil, err
	}
	raw, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	glog.Infof("%s:\n\t%s\n", endpoint, raw)
	return maybeParseJsonp(raw)
}

func (preset *ProviderPreset) GetUserJsonFactory(config *oauth2.Config) GetAuthedUserJson {
	return func(tok *oauth2.Token) (jss []*simplejson.Json, err error) {
		var js *simplejson.Json
		client := config.Client(oauth2.NoContext, tok)
		// OpenIdEndpoint
		if preset.OpenIdEndpoint != "" {
			if js, err = handleEndpoint(preset.OpenIdEndpoint, tok, client); err != nil {
				return nil, err
			}
			jss = append(jss, js)
		}
		// UserEndpoint
		if preset.UserEndpoint != "" {
			if js, err = handleEndpoint(preset.UserEndpoint, tok, client, jss...); err != nil {
				return nil, err
			}
			if preset.JsonUserRoot != "" {
				js = jsGetPath(js, preset.JsonUserRoot)
			}
			jss = append(jss, js)
		}
		return jss, nil
	}
}

func parseMapping(tok *oauth2.Token, jss []*simplejson.Json) func(string) string {
	return func(k string) string {
		if jss != nil {
			for _, js := range jss {
				if v, ok := js.CheckGet(k); ok {
					return toString(v.Interface())
				}
			}
		}
		if tok != nil {
			return toString(tok.Extra(k))
		}
		return ""
	}
}

func toString(i interface{}) string {
	switch s := i.(type) {
	case string:
		return s
	case int64:
		return strconv.FormatInt(s, 10)
	case float64:
		return strconv.FormatFloat(s, 'E', -1, 64)
	default:
		return ""
	}
}

func (preset *ProviderPreset) ParseUserInfo(tok *oauth2.Token, jss []*simplejson.Json) (*userInfo, error) {
	var info userInfo
	if len(jss) != 0 {
		// retrive from jsons of endpoint
		mapping := parseMapping(nil, jss)
		info.Oid = mapping(preset.JsonPathOid)
		if preset.JsonPathName != "" {
			info.Name = mapping(preset.JsonPathName)
		}
		if preset.JsonPathPic != "" {
			info.Picture = mapping(preset.JsonPathPic)
		}
	} else if preset.JsonUserRoot != "" {
		// retrive from sub path of token result
		user, ok := tok.Extra(preset.JsonUserRoot).(map[string]interface{})
		if !ok {
			return nil, ErrJsonFmt
		}
		oid, ok := user[preset.JsonPathOid]
		if !ok {
			return nil, ErrJsonFmt
		}
		info.Oid = toString(oid)
		if preset.JsonPathName != "" {
			info.Name = user[preset.JsonPathName].(string)
		}
		if preset.JsonPathPic != "" {
			info.Picture = user[preset.JsonPathPic].(string)
		}
	} else {
		// retrive directly from token result
		info.Oid = toString(tok.Extra(preset.JsonPathOid))
		if preset.JsonPathName != "" {
			info.Name = tok.Extra(preset.JsonPathName).(string)
		}
		if preset.JsonPathPic != "" {
			info.Picture = tok.Extra(preset.JsonPathPic).(string)
		}
	}
	if info.Oid == "" {
		return nil, ErrJsonFmt
	}
	return &info, nil
}

// almost from satellizer
var ProviderPresets = map[string]ProviderPreset{
	"qq": {
		// must add to brokenAuthHeaderProviders
		// must add text/html to token.go
		TokenURL:       "https://graph.qq.com/oauth2.0/token",
		OpenIdEndpoint: "https://graph.qq.com/oauth2.0/me?access_token=${access_token}",
		UserEndpoint:   "https://graph.qq.com/user/get_user_info?access_token=${access_token}&oauth_consumer_key=${client_id}&openid=${openid}",
		JsonPathOid:    "openid",
		JsonPathName:   "nickname",
		JsonPathPic:    "figureurl_qq_1",
	},
	"baidu": {
		// must add to brokenAuthHeaderProviders
		TokenURL:     "https://openapi.baidu.com/oauth/2.0/token",
		UserEndpoint: "https://openapi.baidu.com/rest/2.0/passport/users/getLoggedInUser?access_token=${access_token}",
		JsonPathOid:  "uid",
		JsonPathName: "uname",
		JsonPathPic:  "portrait", // client parse
	},
	// header Authorization
	"google": {
		TokenURL:     google.Endpoint.TokenURL,
		UserEndpoint: "https://www.googleapis.com/plus/v1/people/me/openIdConnect",
		JsonPathOid:  "sub",
		JsonPathName: "name",
		JsonPathPic:  "picture",
	},
	"facebook": {
		TokenURL:     "https://graph.facebook.com/v2.3/oauth/access_token",
		UserEndpoint: "https://graph.facebook.com/v2.3/me?access_token=${access_token}",
		JsonPathOid:  "id",
		JsonPathName: "name",
		RedirectEnd:  "/",
		// client parse picture
	},
	// header Authorization
	"github": {
		TokenURL:     github.Endpoint.TokenURL,
		UserEndpoint: "https://api.github.com/user",
		JsonPathOid:  "id",
		JsonPathName: "name",
		JsonPathPic:  "avatar_url",
	},
	// user from token result
	"instagram": {
		TokenURL:     "https://api.instagram.com/oauth/access_token",
		JsonUserRoot: "user",
		JsonPathOid:  "id",
		JsonPathName: "username",
		JsonPathPic:  "profile_picture",
	},
	// header Authorization
	"linkedin": {
		TokenURL:     linkedin.Endpoint.TokenURL,
		UserEndpoint: "https://api.linkedin.com/v1/people/~:(id,first-name,email-address,picture-url)?format=json",
		JsonPathOid:  "id",
		JsonPathName: "firstName",
		JsonPathPic:  "pictureUrl",
	},
	"live": {
		TokenURL:     "https://login.live.com/oauth20_token.srf",
		UserEndpoint: "https://apis.live.net/v5.0/me?access_token=${access_token}",
		JsonPathOid:  "id",
		JsonPathName: "name",
	},
	// header Authorization
	"yahoo": {
		TokenURL:     "https://api.login.yahoo.com/oauth2/get_token",
		UserEndpoint: "https://social.yahooapis.com/v1/user/${xoauth_yahoo_guid}/profile?format=json",
		JsonUserRoot: "profile",
		JsonPathOid:  "guid",
		JsonPathName: "nickname",
	},
}
