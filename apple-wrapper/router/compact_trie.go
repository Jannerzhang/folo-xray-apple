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

func routeActionPriority(action RouteAction) int {
	switch action {
	case ActionBlock:
		return 3
	case ActionProxy:
		return 2
	default:
		return 1
	}
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
		if current, ok := m.exact[domain]; !ok || routeActionPriority(action) > routeActionPriority(current) {
			m.exact[domain] = action
		}
	}
}

func (m *DomainMatcher) AddSuffix(suffix string, action RouteAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	suffix = strings.TrimSpace(strings.ToLower(suffix))
	suffix = strings.TrimPrefix(suffix, ".")
	if suffix != "" {
		if current, ok := m.suffixes[suffix]; !ok || routeActionPriority(action) > routeActionPriority(current) {
			m.suffixes[suffix] = action
		}
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

	var best RouteAction
	matched := false
	consider := func(action RouteAction) {
		if !matched || routeActionPriority(action) > routeActionPriority(best) {
			best = action
			matched = true
		}
	}

	// Evaluate every matching layer so an earlier direct rule cannot hide a
	// security block, and a proxy rule cannot be overwritten by direct.
	if action, ok := m.exact[domain]; ok {
		consider(action)
	}

	// Suffix match (e.g. sub.example.com -> matches example.com, com).
	if action, ok := m.suffixes[domain]; ok {
		consider(action)
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' && i+1 < len(domain) {
			sub := domain[i+1:]
			if action, ok := m.suffixes[sub]; ok {
				consider(action)
			}
		}
	}

	// 3. Keyword match
	for _, k := range m.keywords {
		if strings.Contains(domain, k.keyword) {
			consider(k.action)
		}
	}

	return best, matched
}
