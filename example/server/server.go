package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/empirefox/gin-oauth2"
	"github.com/gin-gonic/gin"
	"github.com/itsjamie/gin-cors"
)

func Ok(c *gin.Context) { c.AbortWithStatus(http.StatusOK) }

func main() {
	//  only need for mock oauth-server
	goauth.ProviderPresets["mock"] = goauth.ProviderPreset{
		TokenURL:     "http://127.0.0.1:14000/token",
		UserEndpoint: "http://127.0.0.1:14000/info",
		JsonPathOid:  "oid",
		JsonPathName: "name",
		JsonPathPic:  "pic",
	}

	goauthConfig := &goauth.Config{
		Origin:      "http://localhost:3000",
		NewUserFunc: func() goauth.OauthUser { return &Oauth{} },
		SignAlg:     "HS256",
		//		// called every time when creating token
		//		FindSignKey: func() (string, interface{}) {
		//			// "mykid" will be saved in jwt header as kid
		//			return "mykid", []byte("hmac-sercet")
		//		},
		//		// jwt.Keyfunc, called when verify every time
		//		FindVerifyKey: func(token *jwt.Token) (interface{}, error) {
		//			// we can find the key using "mykid" in token
		//			return []byte("hmac-sercet"), nil
		//		},
	}

	//  only need for mock oauth-server
	goauthConfig.AddProvider("mock", "/auth/mock", "1234", "aabbccdd")

	// add facebook support
	goauthConfig.AddProvider("facebook", "/auth/facebook", os.Getenv("FB_CLIENT_ID"), os.Getenv("FB_CLIENT_SECRET"))

	authMiddleWare := goauth.Middleware(goauthConfig)

	// cors
	corsMiddleware := cors.Middleware(cors.Config{
		Origins:         "http://localhost:3000",
		Methods:         "GET, PUT, POST, DELETE",
		RequestHeaders:  "Origin, Authorization, Content-Type",
		ExposedHeaders:  "",
		MaxAge:          48 * time.Hour,
		Credentials:     false,
		ValidateHeaders: false,
	})

	api := gin.Default()
	api.Use(corsMiddleware)

	api.GET("/clientids.js", func(c *gin.Context) {
		data, _ := json.Marshal(gin.H{
			"mock":     "1234",
			"facebook": os.Getenv("FB_CLIENT_ID"),
		})
		c.String(http.StatusOK, fmt.Sprintf(`var ClientIds=%s;`, data))
	})

	// compatible with Satellizer
	for path := range goauthConfig.Providers {
		api.POST(path, authMiddleWare, Ok)
	}
	//	api.POST("/unlink", goauthConfig.Unlink)
	//	api.POST("/logoff", goauthConfig.Logoff)

	secure := api.Group("/api", authMiddleWare, goauthConfig.MustBindUser)
	secure.GET("/helloWorld", func(c *gin.Context) {
		u, _ := goauthConfig.GetUser(c)
		prd, oid := u.GetOid()
		c.String(http.StatusOK, fmt.Sprintf(`~~~ Hello %s:%s ~~~`, prd, oid))
	})

	api.Run(":9999")
}
