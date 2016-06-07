package main

import (
	"errors"
	"time"

	"github.com/empirefox/tagsjson/tagjson"
)

const (
	UserInfo = 1
)

var (
	ErrLinkSelf      = errors.New("Cannot link account with self")
	ErrUnLinkSelf    = errors.New("Cannot unlink account with self")
	ErrOauthType     = errors.New("Wrong Oauth type")
	ErrUnauthedOauth = errors.New("Oauth not authed")
	ErrMultiLink     = errors.New("Oauth cannot link to multi account")
)

// tagjson: {"UserInfo":"e"}
type Account struct {
	ID     uint    `gorm:"primary_key"                 UserInfo:""`
	Oauths []Oauth `                                   UserInfo:"-"`
}

type user struct {
	oid     string
	account uint
}

var users = map[string]user{}
var accountId uint = 1

// tagjson: {"UserInfo":"e"}
type Oauth struct {
	ID        uint      `gorm:"primary_key"               UserInfo:""`
	CreatedAt time.Time `                                 UserInfo:"-"`
	UpdatedAt time.Time `                                 UserInfo:"-"`
	Name      string    `sql:"type:varchar(128)"          UserInfo:""`
	Account   Account   `                                 UserInfo:""`
	AccountId uint      `                                 UserInfo:""`
	Oid       string    `sql:"type:varchar(128);not null" UserInfo:"-"`
	Provider  string    `sql:"type:varchar(32);not null"  UserInfo:"-"`
	Picture   string    `sql:"type:varchar(128)"          UserInfo:""`
	Disabled  bool      `sql:"default:false"              UserInfo:"-"`
}

// implements goauth.OauthUser

func (o *Oauth) GetOid() (provider, oid string) {
	return o.Provider, o.Oid
}

// return error if login failed, create oauth and account if not found
func (o *Oauth) OnLogin(provider, oid, name, pic string) error {
	// query from db
	dbuser, ok := users[provider]
	if !ok {
		// create user and account to db
		dbuser = user{oid, accountId}
		users[provider] = dbuser
		o.AccountId = accountId
		accountId++
	} else if dbuser.oid != oid {
		// login failed
		return errors.New("Login failed")
	}

	// login ok
	o.AccountId = dbuser.account
	o.Provider = provider
	o.Oid = oid
	o.Name = name
	return nil
}

func (o *Oauth) OnLink(existed interface{}, provider, oid, name, pic string) error {
	if o.AccountId != 0 {
		// already linked to account
		return ErrMultiLink
	}
	o1, ok := existed.(*Oauth)
	if !ok {
		// sometimes we can ignore this
		return ErrOauthType
	}
	if o1.AccountId == 0 {
		// current is not authed
		return ErrUnauthedOauth
	}
	if provider == o1.Provider {
		// do not support multi oauth of the same provider
		return ErrLinkSelf
	}
	// save o to db
	o.Provider = provider
	o.Oid = oid
	o.Name = name
	o.AccountId = o1.AccountId
	return nil
}

// just find oauth, used to verify or bind
func (o *Oauth) Find(provider, oid string) error {
	if dbuser, ok := users[provider]; ok {
		if dbuser.oid == oid {
			// found user from db
			o.AccountId = dbuser.account
			o.Provider = provider
			o.Oid = oid
			return nil
		}
	}
	return errors.New("User not found")
}

// used: gin.H{"token": tokenString, "user": u.Info()}
func (o *Oauth) Info() interface{} {
	info, err := tagjson.MarshalR(o, UserInfo)
	if err != nil {
		return "error"
	}
	return info
}

func (o *Oauth) Valid() bool { return !o.Disabled }
