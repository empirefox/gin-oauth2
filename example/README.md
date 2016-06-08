### the example is more complex than we think

-----

- server(api server) is on port 9999
- client is on port 3000
- oauth-server(mock server) is on port 14000

-----
1. run api server, need set env FB_CLIENT_ID and FB_CLIENT_SECRET

1. run oauth mock server(skip if no need for sign in with mock)

1. run client using
```
npm i & npm start
```
1. browser http://127.0.0.1:3000
