package panel

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	path2 "path"
)

// Debug set the client debug for client
func (c *Client) Debug() {
	c.client.SetDebug(true)
}

func (c *Client) assembleURL(path string) string {
	return path2.Join(c.APIHost + path)
}

func (c *Client) configPath() string {
	if c.NodeType == "shadowsocksr" {
		return "/api/v1/server/shadowsocksrTidalab/config"
	}
	return "/api/v1/server/UniProxy/config"
}

func (c *Client) userPath() string {
	if c.NodeType == "shadowsocksr" {
		return "/api/v1/server/shadowsocksrTidalab/user"
	}
	return "/api/v1/server/UniProxy/user"
}

func (c *Client) submitPath() string {
	if c.NodeType == "shadowsocksr" {
		return "/api/v1/server/shadowsocksrTidalab/submit"
	}
	return "/api/v1/server/UniProxy/push"
}

func (c *Client) alivePath() string {
	return "/api/v1/server/UniProxy/alive"
}

func (c *Client) aliveListPath() string {
	return "/api/v1/server/UniProxy/alivelist"
}

func (c *Client) checkResponse(res *resty.Response, path string, err error) error {
	if err != nil {
		return fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}
	if res.StatusCode() >= 400 {
		body := res.Body()
		return fmt.Errorf("request %s failed: %s", c.assembleURL(path), string(body))
	}
	return nil
}
