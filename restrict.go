package restrict

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/paked/gerrycode/communicator"
)

var (
	pkey []byte
)

func ReadCryptoKey(file string) error {
	privateKey, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	pkey = privateKey

	return nil
}

func R(fn func(http.ResponseWriter, *http.Request, *jwt.Token)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts := r.FormValue("access_token")
		c := communicator.New(w)

		token, err := jwt.Parse(ts, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
			}
			return pkey, nil
		})

		if err != nil {
			c.Fail("You are not using a valid token:" + err.Error())
			return
		}

		if !token.Valid {
			c.Fail("Something obscurely weird happened to your token!")
			return
		}

		fn(w, r, token)
	}
}

func Token(claims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims

	return token.SignedString(pkey)
}
