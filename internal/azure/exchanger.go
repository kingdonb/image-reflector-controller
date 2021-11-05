package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

type acrError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Exchanger struct {
	acrFQDN string
}

func NewExchanger(acrEndpoint string) *Exchanger {
	return &Exchanger{
		acrFQDN: acrEndpoint,
	}
}

func (e *Exchanger) ExchangeACRAccessToken(armToken string) (string, error) {
	exchangeUrl := fmt.Sprintf("https://%s/oauth2/exchange", e.acrFQDN)
	parsedURL, err := url.Parse(exchangeUrl)
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	parameters.Add("grant_type", "access_token")
	parameters.Add("service", parsedURL.Hostname())
	parameters.Add("access_token", armToken)

	resp, err := http.PostForm(exchangeUrl, parameters)
	if err != nil {
		return "", fmt.Errorf("failed to send token exchange request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errors []acrError
		decoder := json.NewDecoder(resp.Body)
		if err = decoder.Decode(&errors); err == nil {
			return "", fmt.Errorf("unexpected status code %d from exchnage request: errors:%s",
				resp.StatusCode, errors)
		}

		return "", fmt.Errorf("unexpected status code %d from exchnage request", resp.StatusCode)
	}

	var tokenResp tokenResponse
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.RefreshToken, nil
}
