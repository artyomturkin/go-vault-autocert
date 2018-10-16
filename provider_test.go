package vac_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/artyomturkin/go-vault-autocert"
)

func TestVaultPKIProvider(t *testing.T) {
	mockH := func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/v1/pki/issue/temp" {
			t.Errorf("wrong path in request: %s. Expected /v1/pki/issue/temp", r.RequestURI)
		}
		if r.Header.Get("X-VAULT-TOKEN") != "test-token" {
			t.Errorf("Vault Token not set in request")
		}

		resp := `{
			"lease_id": "pki/issue/temp/test-lease",
			"renewable": false,
			"lease_duration": 10,
			"data": {
				"certificate": "-----BEGIN CERTIFICATE-----\nMIIDtzCCAp+gAwIBAgIQI34PXN0OPAhFB1R45L4eETANBgkqhkiG9w0BAQsFADBc\nMQswCQYDVQQGEwJLWjEPMA0GA1UEBxMGQWxtYXR5MRIwEAYDVQQKEwlUZXN0IElu\nYy4xKDAmBgNVBAMTH1Rlc3QgSW5jLiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcN\nMTgxMDE2MDc1NjU0WhcNMTkxMDE2MDc1NjU0WjBHMQswCQYDVQQGEwJLWjEPMA0G\nA1UEBxMGQWxtYXR5MRIwEAYDVQQKEwlUZXN0IEluYy4xEzARBgNVBAMMCioudGVt\ncC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYrkM8I+7uB1Sw\nDSTkTybPsm97UhxaRRlbPoAP+AgllOPObOZtjncNVjj2MN8cb8VuKCen5T0jqoOs\nIjZdbp0K4xE3q4ZD+U1lka5yoIipNQs2popLtiVZIS7iYK3/97hl92yV081LAKnh\nYU+f0EdBCkERPUM3cDXqz6FLfFB4aUD8mxhplMgTolGaIqm11gfsHowwiI+P7Fb1\n/b6KB+RXjZXj72FhFw+pdBwUL1xUZent+JnHVoDcNPutG9wZShZpBYoUimu9xcEV\nmHaYFaHuTmcLOYRNP63JEsO2u4Z2zfuRgr/Gxiwr52wa4P2FAcPqBMS/cpMQWoAZ\nqKSs+yoHAgMBAAGjgYkwgYYwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\nAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUcndm30ibpnBUQMnWD557nHsWYmQw\nHwYDVR0jBBgwFoAUjkpT17F4yTIP0Szl5jeLjKQrA74wFQYDVR0RBA4wDIcEfwAA\nAYcEwKgBATANBgkqhkiG9w0BAQsFAAOCAQEAIFrpb8njE2+7mnwnWltGuYQdvhNk\nuwayvA/hRWfzERxbPhV42CnywhyKJ9biKO8HSVVIoFTV4wpySjeDHumenh5pVwS5\nScU229jQuVe1qnb5ikOLhRuf4e4dJc5w+AHQeoeiyCf8ebDWxpiaRLmLy0oQh0pS\nsXHoh8gwF6aWYA+46FhI8SszG2YfR8r5gpOjWN+A85Ziv7kWOW7ukbU6vvr87eXI\nCa7Q7taCB7Wgqp8LGtVsEQotbcC31yIVW3ptguZLUVNpTsXnbvJOqAnuTml4FtOj\nntTVjTEuV09PWEn9cjSjejEC+LUNYkjwvX14a81S80L4ehHTlxwbobg1ZA==\n-----END CERTIFICATE-----\n",
				"issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDpjCCAo6gAwIBAgIRAK0IQuK85qOv1cM+UJid+5swDQYJKoZIhvcNAQELBQAw\nXDELMAkGA1UEBhMCS1oxDzANBgNVBAcTBkFsbWF0eTESMBAGA1UEChMJVGVzdCBJ\nbmMuMSgwJgYDVQQDEx9UZXN0IEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4X\nDTE4MTAxNjA3NTQ1NFoXDTE5MTAxNjA3NTQ1NFowXDELMAkGA1UEBhMCS1oxDzAN\nBgNVBAcTBkFsbWF0eTESMBAGA1UEChMJVGVzdCBJbmMuMSgwJgYDVQQDEx9UZXN0\nIEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAvOcka3OT+/Sux3g2Ob4UyXGjGPm/8KbYdCRNgrGTIBJNE8xp\ndiS774Fi1bPChZwY203QLo9qiIe8MUo8qMTtBc+UgX14UXhU3ZWHUCHo+/KWuELm\ngxovaDXZhbVLWnyUKTAYr3azOgYxJWptNAK/uZPLEk1Ct3296hdRn3CQVlHJuccU\nNlUddx5m8ozTVLQ67TpvYw5ZRS7PlU2b+wNzerbWW02rieNdMlz96VY4DiVc8pIH\nj4GQKS7OIncBx9wn67bpFJhYa5tC8ggaUP2+PIPTXzmOms6FyJxh93bfN1/gWvq2\nPKcqSdJ7ELI/eUjZ5m+jYKnEP9M/twwWjRzRDQIDAQABo2MwYTAOBgNVHQ8BAf8E\nBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUjkpT17F4yTIP0Szl5jeL\njKQrA74wHwYDVR0jBBgwFoAUjkpT17F4yTIP0Szl5jeLjKQrA74wDQYJKoZIhvcN\nAQELBQADggEBAFiKD5r4B8qSOspBXKaLq1Nas8GmKiSdJezchj7lmsYIVGkQXx1x\nuHPNzGcQS/8Fb4KWqxqvraWfN9wPUErC1VvfIEoPOhcvW7OvIwKCGIuYHNfs5mh5\nmYWkPmYZ3hORAcVUzgHuEFOoIM0aMgrlGQ9X8/SwPxCQBfjGvV9tZO7UU8iYfEvK\n8L08iTKNmMheSqqst5XFKBGfUJALuPZYC+VCdgrEYf/Ggug2gt/PQzZDMqqY32ff\n58R5NBA2dfSIHjZyx41TIfitNHpKL86hB+2kIdU+zUSQpiAP6avLmpgXEtQ487Wl\nwKByCj19/HoWmtQy69xxlG5Krzsl0IXTn+Q=\n-----END CERTIFICATE-----\n",
				"ca_chain": "-----BEGIN CERTIFICATE-----\nMIIDpjCCAo6gAwIBAgIRAK0IQuK85qOv1cM+UJid+5swDQYJKoZIhvcNAQELBQAw\nXDELMAkGA1UEBhMCS1oxDzANBgNVBAcTBkFsbWF0eTESMBAGA1UEChMJVGVzdCBJ\nbmMuMSgwJgYDVQQDEx9UZXN0IEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4X\nDTE4MTAxNjA3NTQ1NFoXDTE5MTAxNjA3NTQ1NFowXDELMAkGA1UEBhMCS1oxDzAN\nBgNVBAcTBkFsbWF0eTESMBAGA1UEChMJVGVzdCBJbmMuMSgwJgYDVQQDEx9UZXN0\nIEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAvOcka3OT+/Sux3g2Ob4UyXGjGPm/8KbYdCRNgrGTIBJNE8xp\ndiS774Fi1bPChZwY203QLo9qiIe8MUo8qMTtBc+UgX14UXhU3ZWHUCHo+/KWuELm\ngxovaDXZhbVLWnyUKTAYr3azOgYxJWptNAK/uZPLEk1Ct3296hdRn3CQVlHJuccU\nNlUddx5m8ozTVLQ67TpvYw5ZRS7PlU2b+wNzerbWW02rieNdMlz96VY4DiVc8pIH\nj4GQKS7OIncBx9wn67bpFJhYa5tC8ggaUP2+PIPTXzmOms6FyJxh93bfN1/gWvq2\nPKcqSdJ7ELI/eUjZ5m+jYKnEP9M/twwWjRzRDQIDAQABo2MwYTAOBgNVHQ8BAf8E\nBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUjkpT17F4yTIP0Szl5jeL\njKQrA74wHwYDVR0jBBgwFoAUjkpT17F4yTIP0Szl5jeLjKQrA74wDQYJKoZIhvcN\nAQELBQADggEBAFiKD5r4B8qSOspBXKaLq1Nas8GmKiSdJezchj7lmsYIVGkQXx1x\nuHPNzGcQS/8Fb4KWqxqvraWfN9wPUErC1VvfIEoPOhcvW7OvIwKCGIuYHNfs5mh5\nmYWkPmYZ3hORAcVUzgHuEFOoIM0aMgrlGQ9X8/SwPxCQBfjGvV9tZO7UU8iYfEvK\n8L08iTKNmMheSqqst5XFKBGfUJALuPZYC+VCdgrEYf/Ggug2gt/PQzZDMqqY32ff\n58R5NBA2dfSIHjZyx41TIfitNHpKL86hB+2kIdU+zUSQpiAP6avLmpgXEtQ487Wl\nwKByCj19/HoWmtQy69xxlG5Krzsl0IXTn+Q=\n-----END CERTIFICATE-----\n",
				"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2K5DPCPu7gdUsA0k5E8mz7Jve1IcWkUZWz6AD/gIJZTjzmzm\nbY53DVY49jDfHG/Fbignp+U9I6qDrCI2XW6dCuMRN6uGQ/lNZZGucqCIqTULNqaK\nS7YlWSEu4mCt//e4ZfdsldPNSwCp4WFPn9BHQQpBET1DN3A16s+hS3xQeGlA/JsY\naZTIE6JRmiKptdYH7B6MMIiPj+xW9f2+igfkV42V4+9hYRcPqXQcFC9cVGXp7fiZ\nx1aA3DT7rRvcGUoWaQWKFIprvcXBFZh2mBWh7k5nCzmETT+tyRLDtruGds37kYK/\nxsYsK+dsGuD9hQHD6gTEv3KTEFqAGaikrPsqBwIDAQABAoIBABgVJjvk8oVaIzt9\n+n+1nGaxOlrGgYg27d6KT8l2k9E5fyhOSj4a+3hsAOC8BdAvTA42QFIU1HrGVOQo\n2UoBJUs0eZFqav3bE5MaYf0zgnzr/FcSo4ROtk/1tDRM8onkioYqvdLZO5P+euMl\n4aetin3cGedEm9fpjNSQRykQpBD9zXBrA3uvK8cbroHrDTJtNTa4FETOeYSzxxUs\n5R1LjXgb1WtHviATGxFrF4ZyCOsbRSpr0X/QA/yqqkcEH/NgEGSLgXqCExU38kmi\nAt3LJ4JifHXgZ9Qe5nz5xNhmh4T7HVdCepCcsTIyacS0AmPl0PyYendTcPGPzcBv\n5do3uCECgYEA8YJFkpLaw0Tx1Y8SnobzbFeqUzg0dGUo9DOvU8N9RsnCuB9pQgvZ\n75a341gJxXcGWU02cMLu2b1IQ9HI5VpT07WvoS9oIINH7PwiFD5V+jd2JSZDDxU8\nRLlf77vgFm3GRAsNWh03dV4IbZtiI/84oY9RGHoTUDUCdUIxeDPLUvsCgYEA5a6d\nXR2gl6K0ySqji5+MKZIExslHF0J53nARCvZQ4S+OgLvEWdJQRksIYksQYj82OWhZ\nteS4fpvzFNztN/5dLL+R3f/cOmIrdvqGHKDz5+f6dZ2oO/u/juHcGF39UhvGi7iD\nHCt7QA0lkUv63/4d38YyFtbOu7jgAmX1MgW2t2UCgYBjM8ewNXJ201MjDenwBC7p\nSflExcmGJid0Z+aU2bAT67x4NS7fWk7jA131nKwm2IVbGURLfUbvWbjdYsbKrxfP\n1smVxAtZj5Nz3P2Cozhd13pIODdDcs2WzS6DIwEhNWZDfOa3JVkqdL2xiCn/704r\nztrY2wwj3iJsWAxJ+7yBEQKBgQCKUfpbFXidWVNewtrzPwZ+En3l6Vly3IngN8VL\nwMM8mhNL28iH/2xwqMdHysT3JfJV6E3+iNvDA9AEhHgn/HvIcyY5d9j9IBnk8ULL\nAvNgeggPxP6IATh/p+2Qjyn7xNZxVpE+6cCz9jblpchUFQmQth98OakOzGu7hgOA\nOIitMQKBgHQhF7ZnXd522k2LOcGtrKRS5P7aaEFRx5jW44qorSBxaWDiq/L8R1kQ\n97QMALIsIJbxoY2QOBBZgDbcTOQX/J7m3c3Egia1M/vAfSzJYRQTozMVLj/Gq3hF\ngEoo1phnOZhSQs7z+/ZZe0JtoYLZv8VLk+f7pDvM+QGG/UaPIwhD\n-----END RSA PRIVATE KEY-----\n",
				"private_key_type": "rsa",
				"serial_number": ""
			},
			"warnings": null,
			"auth": null
		}`
		w.Write([]byte(resp))
	}
	ts := httptest.NewServer(http.HandlerFunc(mockH))

	cfg := vac.VaultPKIConfig{
		AdvertisedIPs: []string{
			"127.0.0.1",
			"192.168.1.1",
		},
		CN:            "*.temp.com",
		Path:          "pki",
		RenewModifier: 0.1,
		Role:          "temp",
		Token:         "test-token",
		Address:       ts.URL,
	}

	ctx := context.Background()
	prov, err := vac.NewVaultPKIProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create provider; %v", err)
	}

	tls := &tls.Config{}
	prov.BindTLSConfig(tls)

	cert0, err := tls.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate 0: %v", err)
	}
	cert1, err := tls.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate 1: %v", err)
	}
	if cert0 == nil {
		t.Fatalf("certificate is nil")
	}
	if cert0 != cert1 {
		t.Errorf("certificate is not cached")
	}

	time.Sleep(2 * time.Second)
	cert2, err := tls.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate 2: %v", err)
	}
	if cert0 == cert2 {
		t.Errorf("certificate not updated in time")
	}
}
