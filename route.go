package ldapserver

import "reflect"

const (
	SEARCH   = "SearchRequest"
	BIND     = "BindRequest"
	COMPARE  = "CompareRequest"
	ADD      = "AddRequest"
	MODIFY   = "ModifyRequest"
	DELETE   = "DeleteRequest"
	EXTENDED = "ExtendedRequest"
	ABANDON  = "AbandonRequest"
)

type HandlerFunc func(ResponseWriter, *Message)

type RouteMux struct {
	routes        []*route
	notFoundRoute *route
}

type route struct {
	operation string
	handler   HandlerFunc
	exo_name  LDAPOID
	s_basedn  string
	s_filter  string
}

// Match return true when the *Message matches the route
// conditions
func (r *route) Match(m *Message) bool {
	//log.Printf(" exo = %s", r.exo_name)
	if reflect.TypeOf(m.protocolOp).Name() != r.operation {
		return false
	}

	switch v := m.protocolOp.(type) {
	case ExtendedRequest:
		if "" != r.exo_name {
			if v.GetResponseName() == r.exo_name {
				return true
			}
			return false
		}

	case SearchRequest:
		if "" != r.s_basedn {
			if string(v.GetBaseObject()) == r.s_basedn {
				return true
			}
			return false
		}
	}
	return true
}

func (r *route) BaseDn(dn string) *route {
	r.s_basedn = dn
	return r
}

func (r *route) Filter(pattern string) *route {
	r.s_filter = pattern
	return r
}

func (r *route) RequestName(name LDAPOID) *route {
	r.exo_name = name
	return r
}

// NewRouteMux returns a new *RouteMux
// RouteMux implements ldapserver.Handler
func NewRouteMux() *RouteMux {
	return &RouteMux{}
}

// Handler interface used to serve a LDAP Request message
type Handler interface {
	ServeLDAP(w ResponseWriter, r *Message)
}

func (h *RouteMux) ServeLDAP(w ResponseWriter, r *Message) {

	//find a matching Route
	for _, route := range h.routes {

		//if the route don't match, skip it
		if route.Match(r) == false {
			continue
		}

		route.handler(w, r)
		return
	}

	if h.notFoundRoute != nil {
		h.notFoundRoute.handler(w, r)
	} else {
		res := NewResponse(r.MessageID, LDAPResultUnwillingToPerform)
		res.DiagnosticMessage = "Operation not implemented by server"
		w.Write(res)
	}
}

// Adds a new Route to the Handler
func (h *RouteMux) addRoute(r *route) {
	//and finally append to the list of Routes
	//create the Route
	h.routes = append(h.routes, r)
}

func (h *RouteMux) NotFound(handler HandlerFunc) {
	route := &route{}
	route.handler = handler
	h.notFoundRoute = route
}

func (h *RouteMux) Bind(handler HandlerFunc) *route {
	route := &route{}
	route.operation = BIND
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Search(handler HandlerFunc) *route {
	route := &route{}
	route.operation = SEARCH
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Add(handler HandlerFunc) *route {
	route := &route{}
	route.operation = ADD
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Delete(handler HandlerFunc) *route {
	route := &route{}
	route.operation = DELETE
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Modify(handler HandlerFunc) *route {
	route := &route{}
	route.operation = MODIFY
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Compare(handler HandlerFunc) *route {
	route := &route{}
	route.operation = COMPARE
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Extended(handler HandlerFunc) *route {
	route := &route{}
	route.operation = EXTENDED
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Abandon(handler HandlerFunc) *route {
	route := &route{}
	route.operation = ABANDON
	route.handler = handler
	h.addRoute(route)
	return route
}
