// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// MIMETypeJSON is the media type of every structured resource this hub
// publishes.
const MIMETypeJSON = "application/json"

// MIMETypeMarkdown is the media type of the static, operator-authored
// documentation resources.
const MIMETypeMarkdown = "text/markdown"

// Resource is a fixed-URI MCP resource.
//
// Like [Tool], every field is operator-authored. A cluster name may appear
// inside a resource's *content*, where it is data; it never appears in a
// resource's name or description, where it would be trusted text.
type Resource struct {
	// URI is the canonical identifier, e.g. "fleet://clusters".
	URI string
	// Name is the programmatic name.
	Name string
	// Title is the human-facing display name.
	Title string
	// Description tells the model what the resource answers.
	Description string
	// MIMEType is the content type. Empty means [MIMETypeJSON].
	MIMEType string
}

// ResourceTemplate is a parameterised MCP resource, e.g.
// "fleet://clusters/{name}".
type ResourceTemplate struct {
	// URITemplate is an RFC 6570 template.
	URITemplate string
	// Name is the programmatic name.
	Name string
	// Title is the human-facing display name.
	Title string
	// Description tells the model what the resource answers.
	Description string
	// MIMEType is the content type. Empty means [MIMETypeJSON].
	MIMEType string
}

// ResourceRequest is what a resource handler sees.
type ResourceRequest struct {
	// URI is the concrete URI that was read, with template variables already
	// substituted by the client.
	URI string
	// Token is the authenticated caller, or nil.
	Token *TokenInfo
}

// Principal returns the verified principal, or nil. It is nil-safe.
func (r *ResourceRequest) Principal() *fleet.Principal {
	if r == nil || r.Token == nil {
		return nil
	}
	return r.Token.Principal
}

// ResourceContent is one resource body.
type ResourceContent struct {
	// MIMEType overrides the registered media type when non-empty.
	MIMEType string
	// Text is the body.
	Text string
}

// ResourceFunc produces a resource body. Returning an error makes the read a
// protocol error, which is correct: a resource that cannot be read is not a
// fact about the monitored world that a model can reason its way around.
type ResourceFunc func(ctx context.Context, req *ResourceRequest) (ResourceContent, error)

// AddResource registers a fixed-URI resource.
func (s *Server) AddResource(r Resource, h ResourceFunc) {
	mime := r.MIMEType
	if mime == "" {
		mime = MIMETypeJSON
	}
	s.mcp.AddResource(&mcp.Resource{
		URI:         r.URI,
		Name:        r.Name,
		Title:       r.Title,
		Description: r.Description,
		MIMEType:    mime,
	}, resourceHandler(mime, h))
	s.record(&s.resources, r.URI)
}

// AddResourceTemplate registers a parameterised resource.
func (s *Server) AddResourceTemplate(t ResourceTemplate, h ResourceFunc) {
	mime := t.MIMEType
	if mime == "" {
		mime = MIMETypeJSON
	}
	s.mcp.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: t.URITemplate,
		Name:        t.Name,
		Title:       t.Title,
		Description: t.Description,
		MIMEType:    mime,
	}, resourceHandler(mime, h))
	s.record(&s.templates, t.URITemplate)
}

// resourceHandler adapts a [ResourceFunc] to the SDK's handler signature.
func resourceHandler(mime string, h ResourceFunc) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		rr := &ResourceRequest{}
		if req != nil && req.Params != nil {
			rr.URI = req.Params.URI
		}
		if req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
			ti := req.Extra.TokenInfo
			rr.Token = &TokenInfo{
				Subject:    ti.UserID,
				Scopes:     ti.Scopes,
				Expiration: ti.Expiration,
				Principal:  PrincipalOf(ti.Extra),
			}
		}
		content, err := h(ctx, rr)
		if err != nil {
			return nil, err
		}
		ct := content.MIMEType
		if ct == "" {
			ct = mime
		}
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      rr.URI,
				MIMEType: ct,
				Text:     content.Text,
			}},
		}, nil
	}
}
