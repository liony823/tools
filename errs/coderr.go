// Copyright © 2023 OpenIM. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errs

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/liony823/tools/errs/stack"
)

const stackSkip = 4

var DefaultCodeRelation = newCodeRelation()

type CodeError interface {
	Code() int
	Msg() string
	Detail() string
	WithDetail(detail string) CodeError
	Error
}

func NewCodeError(code int, msg string) CodeError {
	return &codeError{
		code: code,
		msg:  msg,
	}
}

type codeError struct {
	code   int
	msg    string
	detail string
}

func (e *codeError) Code() int {
	return e.code
}

func (e *codeError) Msg() string {
	return e.msg
}

func (e *codeError) Detail() string {
	return e.detail
}

func (e *codeError) WithDetail(detail string) CodeError {
	var d string
	if e.detail == "" {
		d = detail
	} else {
		d = e.detail + ", " + detail
	}
	return &codeError{
		code:   e.code,
		msg:    e.msg,
		detail: d,
	}
}

func (e *codeError) Wrap() error {
	return stack.New(e, stackSkip)
}

func (e *codeError) WrapMsg(msg string, kv ...any) error {
	err := fmt.Errorf("%w: %s", e, toString(msg, kv))
	return stack.New(err, stackSkip)
}

func (e *codeError) Is(err error) bool {
	codeErr, ok := Unwrap(err).(CodeError)
	if !ok {
		if err == nil && e == nil {
			return true
		}
		return false
	}
	if e == nil {
		return false
	}
	code := codeErr.Code()
	if e.code == code {
		return true
	}
	return DefaultCodeRelation.Is(e.code, code)
}

const initialCapacity = 3

func (e *codeError) Error() string {
	v := make([]string, 0, initialCapacity)
	v = append(v, strconv.Itoa(e.code), e.msg)

	if e.detail != "" {
		v = append(v, e.detail)
	}

	return strings.Join(v, " ")
}

func Unwrap(err error) error {
	for err != nil {
		unwrap, ok := err.(interface {
			Unwrap() error
		})
		if !ok {
			break
		}
		err = unwrap.Unwrap()
	}
	return err
}

func Wrap(err error) error {
	if err == nil {
		return nil
	}
	return stack.New(err, stackSkip)
}

func WrapMsg(err error, msg string, kv ...any) error {
	if err == nil {
		return nil
	}
	err = fmt.Errorf("%w: %s", err, toString(msg, kv))
	return stack.New(err, stackSkip)
}

type CodeRelation interface {
	Add(codes ...int) error
	Is(parent, child int) bool
}

func newCodeRelation() CodeRelation {
	return &codeRelation{m: make(map[int]map[int]struct{})}
}

type codeRelation struct {
	m map[int]map[int]struct{}
}

const minimumCodesLength = 2

func (r *codeRelation) Add(codes ...int) error {
	if len(codes) < minimumCodesLength {
		return New("codes length must be greater than 2", "codes", codes).Wrap()
	}
	for i := 1; i < len(codes); i++ {
		parent := codes[i-1]
		s, ok := r.m[parent]
		if !ok {
			s = make(map[int]struct{})
			r.m[parent] = s
		}
		for _, code := range codes[i:] {
			s[code] = struct{}{}
		}
	}
	return nil
}

func (r *codeRelation) Is(parent, child int) bool {
	if parent == child {
		return true
	}
	s, ok := r.m[parent]
	if !ok {
		return false
	}
	_, ok = s[child]
	return ok
}
