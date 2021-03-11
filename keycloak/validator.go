package keycloak

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func panicIf(e error) {
	if e != nil {
		panic(e)
	}
}

func getEnv(key string) string {
	env := os.Getenv(key)
	if key == "" {
		panic(fmt.Sprintf("No [%s] env", key))
	}
	return env
}

func ValidateEnv(token string) map[string]interface{} {
	server := getEnv("KEYCLOAK_SERVER")
	realm := getEnv("KEYCLOAK_REALM")
	return Validate(server, realm, token)
}

func Validate(server string, realm string, token string) map[string]interface{} {
	u, err := url.Parse(fmt.Sprintf("https://%s/auth/realms/%s/protocol/openid-connect/userinfo", server, realm))
	panicIf(err)
	var t string
	if strings.HasPrefix(token, "Bearer ") {
		t = token
	} else {
		t = fmt.Sprintf("Bearer %s", token)
	}
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: map[string][]string{
			"Authorization": {t},
		},
	}
	res, err := http.DefaultClient.Do(req)
	panicIf(err)
	data, err := ioutil.ReadAll(res.Body)
	panicIf(err)
	err = res.Body.Close()
	panicIf(err)
	claims := make(map[string]interface{})
	err = json.Unmarshal(data, &claims)
	panicIf(err)
	if res.StatusCode != 200 {
		panic(fmt.Sprintf("%v", claims))
	}
	return claims
}
