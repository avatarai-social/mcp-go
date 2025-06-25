package transport

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// SetHTTPClient 设置自定义的 HTTP client
func (h *OAuthHandler) SetHTTPClient(client *http.Client) {
	h.httpClient = client
}

// CreateDebugHTTPClient 创建一个带有调试功能的 HTTP client
func CreateDebugHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &debugTransport{
			base: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		// 禁用自动重定向，手动处理重定向以便调试
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			logrus.Infof("🔄 MCP OAuth: Redirect detected from %s to %s", via[len(via)-1].URL.String(), req.URL.String())
			logrus.Infof("🔄 MCP OAuth: Redirect chain length: %d", len(via))
			for i, r := range via {
				logrus.Infof("🔄 MCP OAuth: Redirect [%d]: %s", i, r.URL.String())
			}
			// 允许最多 10 次重定向
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

func CreateDebugHTTPClientWithProxy(proxyIP string, proxyPort string) *http.Client {
	var transport *http.Transport

	if proxyIP == "" || proxyPort == "" {
		logrus.Infof("🌐 MCP OAuth: Creating client without proxy")
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else {
		// 构建代理 URL
		proxyURL, err := url.Parse("http://" + proxyIP + ":" + proxyPort)
		if err != nil {
			logrus.WithError(err).Error("❌ MCP OAuth: Failed to parse proxy URL")
			// 如果代理 URL 解析失败，返回不带代理的客户端
			return CreateDebugHTTPClient()
		}

		logrus.Infof("🌐 MCP OAuth: Creating client with proxy: %s", proxyURL.String())

		// 创建带代理的 Transport
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Proxy: func(req *http.Request) (*url.URL, error) {
				// 检查是否是 localhost 或 127.0.0.1
				host := req.URL.Hostname()
				if host == "localhost" || host == "127.0.0.1" || strings.HasPrefix(host, "127.") {
					logrus.Infof("🏠 MCP OAuth: Bypassing proxy for local host: %s", host)
					return nil, nil // 不使用代理
				}
				logrus.Infof("🌐 MCP OAuth: Using proxy for host: %s", host)
				return proxyURL, nil // 使用代理
			},
		}
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &debugTransport{
			base: transport,
		},
		// 禁用自动重定向，手动处理重定向以便调试
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			logrus.Infof("🔄 MCP OAuth: Redirect detected from %s to %s", via[len(via)-1].URL.String(), req.URL.String())
			logrus.Infof("🔄 MCP OAuth: Redirect chain length: %d", len(via))
			for i, r := range via {
				logrus.Infof("🔄 MCP OAuth: Redirect [%d]: %s", i, r.URL.String())
			}
			// 允许最多 10 次重定向
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

// debugTransport 包装 HTTP transport 以添加调试功能
type debugTransport struct {
	base http.RoundTripper
}

func (t *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 记录请求开始时间
	startTime := time.Now()

	// 打印请求基本信息
	logrus.Infof("🚀 MCP OAuth: Starting request to %s %s", req.Method, req.URL.String())
	logrus.Infof("🏠 MCP OAuth: Target host: %s", req.URL.Hostname())
	logrus.Infof("🔒 MCP OAuth: Using HTTPS: %t", req.URL.Scheme == "https")

	// 打印请求头
	logrus.Infof("📋 MCP OAuth: Request headers:")
	for key, values := range req.Header {
		for _, value := range values {
			logrus.Infof("   %s: %s", key, value)
		}
	}

	// 打印完整请求信息（可选，可能很长）
	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		logrus.WithError(err).Error("❌ MCP OAuth: Failed to dump request")
	} else {
		logrus.Infof("📝 MCP OAuth: Full request dump:\n%s", string(reqDump))
	}

	// 执行请求
	resp, err := t.base.RoundTrip(req)

	// 计算请求耗时
	duration := time.Since(startTime)

	if err != nil {
		logrus.WithError(err).Errorf("❌ MCP OAuth: Request failed after %v", duration)

		// 详细分析错误类型
		if urlErr, ok := err.(*url.Error); ok {
			logrus.Errorf("❌ MCP OAuth: URL Error - Op: %s, URL: %s", urlErr.Op, urlErr.URL)
			if urlErr.Timeout() {
				logrus.Errorf("❌ MCP OAuth: Request timeout")
			}
			if urlErr.Temporary() {
				logrus.Errorf("❌ MCP OAuth: Temporary error")
			}
		}

		return nil, err
	}

	// 打印响应基本信息
	logrus.Infof("✅ MCP OAuth: Request completed in %v", duration)
	logrus.Infof("📊 MCP OAuth: Response status: %d %s", resp.StatusCode, resp.Status)

	// 检查是否是重定向响应
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		logrus.Infof("🔄 MCP OAuth: Redirect response - Location: %s", location)
	}

	// 打印响应头
	logrus.Infof("📋 MCP OAuth: Response headers:")
	for key, values := range resp.Header {
		for _, value := range values {
			logrus.Infof("   %s: %s", key, value)
		}
	}

	// 打印完整响应信息（可选，可能很长）
	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		logrus.WithError(err).Error("❌ MCP OAuth: Failed to dump response")
	} else {
		logrus.Infof("📝 MCP OAuth: Full response dump:\n%s", string(respDump))
	}

	return resp, nil
}

