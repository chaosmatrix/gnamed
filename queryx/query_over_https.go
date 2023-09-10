package queryx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/configx"
	"gnamed/libnamed"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

var (
	ErrDoHServerRefused = errors.New("doh server response status_code 403")
	ErrDoHServerFailure = errors.New("doh server response status_code not 2xx")
)

// against fingerprint
func setRequestHeader(req *http.Request) {
	rv := rand.Int() & 7
	switch rv {
	case 0, 7:
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Add("Accept-Language", "en;q=0.9")
		req.Header.Set("Dnt", "1")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
	case 1, 6:
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Add("Accept-Language", "en;q=0.5")
		req.Header.Set("DNT", "1")
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36")
	case 2, 5:
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Add("Accept-Language", "en;q=0.5")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36")
	default:
	}
}

func clientDo(doh *configx.DOHServer, req *http.Request) (*http.Response, error) {
	setRequestHeader(req)
	return doh.GetClient().Do(req)
}

// Google Json
// curl --request GET --header "Accept: application/dns-json" "https://dns.google.com/resolve?name=www.google.com&type=a"
func queryDoHJson(r *dns.Msg, doh *configx.DOHServer, logEvent *zerolog.Event) (*dns.Msg, error) {

	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	name := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]
	dohUrl := doh.Url
	if strings.HasSuffix(dohUrl, "?") {
		dohUrl += "name=" + name + "&type=" + qtype
	} else {
		dohUrl += "?name=" + name + "&type=" + qtype
	}

	logEvent.Str("method", doh.Method).Str("doh_url", dohUrl)

	req, err := http.NewRequest(doh.Method, dohUrl, nil)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}

	for hk, hs := range doh.Headers {
		for _, hv := range hs {
			req.Header.Add(hk, hv)
		}
	}

	if hs, found := doh.Headers["Host"]; found {
		if len(hs) > 0 {
			req.Host = hs[0]
		}
	}
	if _, found := doh.Headers["Accept"]; !found {
		req.Header.Set("Accept", configx.DOHAcceptHeaderTypeJSON)
	}

	resp, err := clientDo(doh, req)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	defer resp.Body.Close()

	logEvent.Int("status_code", resp.StatusCode).Str("http_version", resp.Proto)
	if resp.StatusCode == http.StatusForbidden {
		rmsg.Rcode = dns.RcodeRefused
		return rmsg, ErrDoHServerRefused
	} else if resp.StatusCode != http.StatusOK {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ErrDoHServerFailure
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}

	var dohJson libnamed.DOHJson
	err = json.Unmarshal(body, &dohJson)
	if err != nil {
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}

	/*
		for _, ans := range dohJson.Question {
			question := dns.Question{
				Name:  ans.Name,
				Qtype: ans.Type,
			}
			rmsg.Question = append(rmsg.Question, question)
		}
	*/
	for _, ans := range dohJson.Answer {
		//example.com.              0       IN      A       1.2.3.4
		rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
		if err != nil {
			rmsg.Rcode = dns.RcodeFormatError
			return rmsg, err
		}
		rmsg.Answer = append(rmsg.Answer, rr)
	}
	for _, ans := range dohJson.Authority {
		rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
		if err != nil {
			rmsg.Rcode = dns.RcodeFormatError
			return rmsg, err
		}
		rmsg.Ns = append(rmsg.Ns, rr)
	}
	/*
		for _, ans := range dohJson.Aditional {
			rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
			if err != nil {
				_logEvent.Err(err).Msg("")
				return err
			}
			rmsg.Extra = append(rmsg.Extra, rr)
		}
	*/
	if len(rmsg.Answer) == 0 {
		rmsg.Rcode = dns.RcodeNameError
	}
	return rmsg, err
}

// DOH Format: RFC8484
// content-type: application/dns-message
// request body: encoded dns message (bytes), only contains Question Sections
// response body: encoded dns message (bytes), contain Question/Answer/... Sections
func queryDoHRFC8484(r *dns.Msg, doh *configx.DOHServer, logEvent *zerolog.Event) (*dns.Msg, error) {

	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	bmsg, err := r.Pack()
	if err != nil {
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}

	dohUrl := doh.Url
	var bodyReader io.Reader
	if doh.Method == http.MethodPost {
		bodyReader = bytes.NewReader(bmsg)
	} else if doh.Method == http.MethodGet {
		dohUrl = doh.Url + "?dns=" + base64.RawURLEncoding.EncodeToString(bmsg)
		bodyReader = nil
	}
	logEvent.Str("method", doh.Method).Str("doh_url", dohUrl)

	req, err := http.NewRequest(doh.Method, dohUrl, bodyReader)
	if err != nil {
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}
	/*
		// bug: multi-thread point to same map
		if len(doh.Headers) != 0 {
			req.Header = doh.Headers
		}
	*/

	for hk, hs := range doh.Headers {
		for _, hv := range hs {
			req.Header.Add(hk, hv)

			if http.CanonicalHeaderKey(hk) == "Host" {
				req.Host = hv
			}
		}
	}

	// "Accept" & "Content-Type" must set
	req.Header.Set("Accept", configx.DOHAccetpHeaderTypeRFC8484)

	if req.Method == http.MethodPost {
		req.Header.Set("Content-Type", configx.DOHAccetpHeaderTypeRFC8484)
	}

	resp, err := clientDo(doh, req)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	defer resp.Body.Close()

	logEvent.Int("status_code", resp.StatusCode).Str("http_version", resp.Proto)
	if resp.StatusCode == http.StatusForbidden {
		rmsg.Rcode = dns.RcodeRefused
		return rmsg, ErrDoHServerRefused
	} else if resp.StatusCode != http.StatusOK {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ErrDoHServerFailure
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	err = rmsg.Unpack(body)
	if err != nil {
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}
	return rmsg, err
}

func queryDoH(dc *libnamed.DConnection, doh *configx.DOHServer) (*dns.Msg, error) {

	r := dc.OutgoingMsg
	subEvent := dc.SubLog

	oId := r.Id
	r.Id = 0
	subEvent.Str("protocol", configx.ProtocolTypeDoH).Str("network", "tcp").Str("doh_msg_type", string(doh.Format)).
		Uint16("id", r.Id).Str("name", r.Question[0].Name)

	resp := new(dns.Msg)
	var err error

	start := time.Now()
	switch doh.Format {
	case configx.DOHMsgTypeJSON:
		resp, err = queryDoHJson(r, doh, subEvent)
	case configx.DOHMsgTypeRFC8484:
		resp, err = queryDoHRFC8484(r, doh, subEvent)
	default:
		err = fmt.Errorf("DOH Format '%s' not support", doh.Format)
	}

	subEvent.Dur("latancy", time.Since(start)).Err(err)

	r.Id = oId
	if err == nil {
		resp.Id = oId
	}
	return resp, err
}
