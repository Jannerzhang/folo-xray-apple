// SPDX-License-Identifier: MPL-2.0
package router

import (
	"strings"
	"sync"
)

type DomainMatcher struct {
	mu       sync.RWMutex
	exact    map[string]RouteAction
	suffixes map[string]RouteAction
	keywords []keywordRule
}

type keywordRule struct {
	keyword string
	action  RouteAction
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{
		exact:    make(map[string]RouteAction),
		suffixes: make(map[string]RouteAction),
	}
}

func (m *DomainMatcher) AddExact(domain string, action RouteAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain != "" {
		m.exact[domain] = action
	}
}

func (m *DomainMatcher) AddSuffix(suffix string, action RouteAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	suffix = strings.TrimSpace(strings.ToLower(suffix))
	suffix = strings.TrimPrefix(suffix, ".")
	if suffix != "" {
		m.suffixes[suffix] = action
	}
}

func (m *DomainMatcher) AddKeyword(keyword string, action RouteAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keyword = strings.TrimSpace(strings.ToLower(keyword))
	if keyword != "" {
		m.keywords = append(m.keywords, keywordRule{keyword: keyword, action: action})
	}
}

func (m *DomainMatcher) Match(domain string) (RouteAction, bool) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ActionProxy, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Exact match
	if action, ok := m.exact[domain]; ok {
		return action, true
	}

	// 2. Suffix match (e.g. sub.example.com -> matches example.com, com)
	// Check full domain as suffix first
	if action, ok := m.suffixes[domain]; ok {
		return action, true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' && i+1 < len(domain) {
			sub := domain[i+1:]
			if action, ok := m.suffixes[sub]; ok {
				return action, true
			}
		}
	}

	// 3. Keyword match
	for _, k := range m.keywords {
		if strings.Contains(domain, k.keyword) {
			return k.action, true
		}
	}

	return ActionProxy, false
}
