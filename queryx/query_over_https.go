package queryx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/configx"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrDoHServerRefused = errors.New("doh server response status_code 403")
	ErrDoHServerFailure = errors.New("doh server response status_code not 2xx")
)

// Google JSON Format
type GQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type GAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  int64  `json:"TTL"`
	Data string `json:"data"`
}

type GResJson struct {
	Status    int         `json:"Status"`
	TC        bool        `json:"TC"`
	RD        bool        `json:"RD"`
	RA        bool        `json:"RA"`
	AD        bool        `json:"AD"`
	CD        bool        `json:"CD"`
	Question  []GQuestion `json:"Question"`
	Answer    []GAnswer   `json:"Answer"`
	Authority []GAnswer   `json:"Authority,omitempty"`
	Aditional []string    `json:"Aditional,omitempty"` // ?
	ECS       string      `json:"edns_client_subnet,omitempty"`
	Comment   string      `json:"Comment,omitempty"`
}

/*
// Google Json
curl --location --request GET "https://dns.google.com/resolve?name=www.google.com&type=a" \
 --header "Accept: application/dns-json"
*/

func queryDoHJson(r *dns.Msg, doh *configx.DOHServer) (*dns.Msg, error) {
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

	req, err := http.NewRequest(doh.Method, dohUrl, nil)
	if err != nil {
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
	resp, err := client.Do(req)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	if resp.StatusCode == http.StatusForbidden {
		rmsg.Rcode = dns.RcodeRefused
		return rmsg, ErrDoHServerRefused
	} else if resp.StatusCode != http.StatusOK {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ErrDoHServerFailure
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	var gresp GResJson
	err = json.Unmarshal(body, &gresp)
	if err != nil {
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}

	/*
		for _, ans := range gresp.Question {
			question := dns.Question{
				Name:  ans.Name,
				Qtype: ans.Type,
			}
			rmsg.Question = append(rmsg.Question, question)
		}
	*/
	for _, ans := range gresp.Answer {
		//example.com.              0       IN      A       1.2.3.4
		rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
		if err != nil {
			rmsg.Rcode = dns.RcodeFormatError
			return rmsg, err
		}
		rmsg.Answer = append(rmsg.Answer, rr)
	}
	for _, ans := range gresp.Authority {
		rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
		if err != nil {
			rmsg.Rcode = dns.RcodeFormatError
			return rmsg, err
		}
		rmsg.Ns = append(rmsg.Ns, rr)
	}
	/*
		for _, ans := range gresp.Aditional {
			rr, err := dns.NewRR(ans.Name + "\t" + strconv.Itoa(int(ans.TTL)) + "\tIN\t" + dns.TypeToString[ans.Type] + "\t" + ans.Data)
			if err != nil {
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
func queryDoHRFC8484(r *dns.Msg, doh *configx.DOHServer) (*dns.Msg, error) {

	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	bmsg, err := r.Pack()
	if err != nil {
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, err
	}
	req, err := http.NewRequest(doh.Method, doh.Url, bytes.NewReader(bmsg))
	if err != nil {
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
	resp, err := client.Do(req)
	if err != nil {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	if resp.StatusCode == http.StatusForbidden {
		rmsg.Rcode = dns.RcodeRefused
		return rmsg, ErrDoHServerRefused
	} else if resp.StatusCode != http.StatusOK {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ErrDoHServerFailure
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
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
