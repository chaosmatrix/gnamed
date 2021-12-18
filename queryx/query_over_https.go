package queryx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/configx"
	"gnamed/libnamed"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrDoHServerRefused = errors.New("doh server response status_code 403")
	ErrDoHServerFailure = errors.New("doh server response status_code not 2xx")
)

// Google Json
// curl --request GET --header "Accept: application/dns-json" "https://dns.google.com/resolve?name=www.google.com&type=a"
//
func queryDoHJson(r *dns.Msg, doh *configx.DOHServer) (*dns.Msg, error) {

	_logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDoH).Str("doh_msg_type", string(configx.DOHMsgTypeJSON))

	_logEvent.Uint16("id", r.Id)

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

	_logEvent.Str("name", name).Str("type", qtype).Str("method", doh.Method).Str("doh_url", dohUrl)

	req, err := http.NewRequest(doh.Method, dohUrl, nil)
	if err != nil {
		_logEvent.Err(err).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}

	if len(doh.Headers) != 0 {
		req.Header = doh.Headers
	}
	if _, found := doh.Headers["Accept"]; !found {
		req.Header.Set("Accept", configx.DOHAcceptHeaderTypeJSON)
	}

	client := &http.Client{
		Timeout: doh.Timeout.ConnectDuration + doh.Timeout.ReadDuration + doh.Timeout.WriteDuration,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		_logEvent.Dur("latency", time.Since(start)).Err(err).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}

	_logEvent.Int("status_code", resp.StatusCode)
	if resp.StatusCode == http.StatusForbidden {
		_logEvent.Dur("latency", time.Since(start)).Msg("")
		rmsg.Rcode = dns.RcodeRefused
		return rmsg, ErrDoHServerRefused
	} else if resp.StatusCode != http.StatusOK {
		_logEvent.Dur("latency", time.Since(start)).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ErrDoHServerFailure
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	_logEvent.Dur("latency", time.Since(start))
	if err != nil {
		_logEvent.Err(err).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}

	var dohJson libnamed.DOHJson
	err = json.Unmarshal(body, &dohJson)
	if err != nil {
		_logEvent.Err(err).Msg("")
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
			_logEvent.Err(err).Msg("")
			rmsg.Rcode = dns.RcodeFormatError
			return rmsg, err
		}
		rmsg.Answer = append(rmsg.Answer, rr)
	}
	for _, ans := range dohJson.Authority {
		rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
		if err != nil {
			_logEvent.Err(err).Msg("")
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
	_logEvent.Err(err).Msg("")
	return rmsg, err
}

// DOH Format: RFC8484
// content-type: application/dns-message
// request body: encoded dns message (bytes), only contains Question Sections
// response body: encoded dns message (bytes), contain Question/Answer/... Sections
func queryDoHRFC8484(r *dns.Msg, doh *configx.DOHServer) (*dns.Msg, error) {
	_logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDoH).Str("doh_msg_type", string(configx.DOHMsgTypeRFC8484))

	_logEvent.Uint16("id", r.Id)

	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	bmsg, err := r.Pack()
	if err != nil {
		_logEvent.Err(err).Msg("")
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}
	_logEvent.Str("name", r.Question[0].Name).Str("type", dns.TypeToString[r.Question[0].Qtype]).Str("method", doh.Method).Str("doh_url", doh.Url)
	req, err := http.NewRequest(doh.Method, doh.Url, bytes.NewReader(bmsg))
	if err != nil {
		_logEvent.Err(err).Msg("")
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}
	if len(doh.Headers) != 0 {
		req.Header = doh.Headers
	}
	if _, found := doh.Headers["Accept"]; !found {
		req.Header.Set("Accept", configx.DOHAccetpHeaderTypeRFC8484)
	}

	client := &http.Client{
		Timeout: doh.Timeout.ConnectDuration + doh.Timeout.ReadDuration + doh.Timeout.WriteDuration,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		_logEvent.Dur("latency", time.Since(start)).Err(err).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	_logEvent.Int("status_code", resp.StatusCode)
	if resp.StatusCode == http.StatusForbidden {
		_logEvent.Dur("latency", time.Since(start)).Msg("")
		rmsg.Rcode = dns.RcodeRefused
		return rmsg, ErrDoHServerRefused
	} else if resp.StatusCode != http.StatusOK {
		_logEvent.Dur("latency", time.Since(start)).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ErrDoHServerFailure
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	_logEvent.Dur("latency", time.Since(start))
	if err != nil {
		_logEvent.Err(err).Msg("")
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	err = rmsg.Unpack(body)
	if err != nil {
		_logEvent.Err(err).Msg("")
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}
	_logEvent.Err(err).Msg("")
	return rmsg, err
}

func queryDoH(r *dns.Msg, doh *configx.DOHServer) (*dns.Msg, error) {
	switch doh.Format {
	case configx.DOHMsgTypeJSON:
		return queryDoHJson(r, doh)
	case configx.DOHMsgTypeRFC8484:
		return queryDoHRFC8484(r, doh)
	default:
		return r.Copy(), fmt.Errorf("DOH Format '%s' not support", doh.Format)
	}
}
