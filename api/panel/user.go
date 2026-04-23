package panel

import (
	"fmt"
	"strings"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type TidalabUserInfo struct {
	Id            int    `json:"id"`
	Port          int    `json:"port"`
	Cipher        string `json:"cipher"`
	Protocol      string `json:"protocol"`
	ProtocolParam string `json:"protocol_param"`
	Obfs          string `json:"obfs"`
	ObfsParam     string `json:"obfs_param"`
	Secret        string `json:"secret"`
	Password      string `json:"password"`
	Method        string `json:"method"`
}

type TidalabUserListBody struct {
	Msg  string            `json:"msg"`
	Data []TidalabUserInfo `json:"data"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList() ([]UserInfo, error) {
	path := c.userPath()
	r, err := c.client.R().
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true).
		Get(path)
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	userlist := &UserListBody{}
	if c.NodeType == "shadowsocksr" {
		payload := &TidalabUserListBody{}
		if err := json.Unmarshal(r.Body(), payload); err != nil {
			return nil, fmt.Errorf("decode shadowsocksr user list error: %w", err)
		}
		for _, item := range payload.Data {
			password := item.Password
			if password == "" {
				password = item.Secret
			}
			userlist.Users = append(userlist.Users, UserInfo{
				Id:          item.Id,
				Uuid:        password,
				SpeedLimit:  0,
				DeviceLimit: 0,
			})
		}
		c.userEtag = r.Header().Get("ETag")
		return userlist.Users, nil
	}

	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(r.RawResponse.Body)
		if err := decoder.Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else {
		dec := jsontext.NewDecoder(r.RawResponse.Body)
		for {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: %w", err)
			}
			if tok.Kind() == '"' && tok.String() == "users" {
				break
			}
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if tok.Kind() != '[' {
			return nil, fmt.Errorf(`decode user list error: expected "users" array`)
		}
		for dec.PeekKind() != ']' {
			val, err := dec.ReadValue()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: read user object: %w", err)
			}
			var u UserInfo
			if err := json.Unmarshal(val, &u); err != nil {
				return nil, fmt.Errorf("decode user list error: unmarshal user error: %w", err)
			}
			userlist.Users = append(userlist.Users, u)
		}
	}
	c.userEtag = r.Header().Get("ETag")
	return userlist.Users, nil
}

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive() (map[int]int, error) {
	c.AliveMap = &AliveMap{}
	if c.NodeType == "shadowsocksr" {
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	path := c.aliveListPath()
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil || r.StatusCode() >= 399 {
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	if r == nil || r.RawResponse == nil {
		fmt.Printf("received nil response or raw response")
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		fmt.Printf("unmarshal user alive list error: %s", err)
		c.AliveMap.Alive = make(map[int]int)
	}

	return c.AliveMap.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	path := c.submitPath()
	if c.NodeType == "shadowsocksr" {
		data := make([]map[string]int64, 0, len(userTraffic))
		for i := range userTraffic {
			data = append(data, map[string]int64{
				"user_id": int64(userTraffic[i].UID),
				"u":       userTraffic[i].Upload,
				"d":       userTraffic[i].Download,
			})
		}
		r, err := c.client.R().
			SetBody(data).
			ForceContentType("application/json").
			Post(path)
		err = c.checkResponse(r, path, err)
		if err != nil {
			return err
		}
		return nil
	}

	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		data[userTraffic[i].UID] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
	}
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error {
	if c.NodeType == "shadowsocksr" {
		return nil
	}
	path := c.alivePath()
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)

	if err != nil {
		return nil
	}

	return nil
}
