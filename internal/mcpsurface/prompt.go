// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// PromptArgument is one templating argument of a prompt.
type PromptArgument struct {
	// Name is the argument key.
	Name string
	// Title is the human-facing display name.
	Title string
	// Description explains what to put here.
	Description string
	// Required fails the prompt when the argument is absent.
	Required bool
}

// Prompt is an operator-authored workflow the model can invoke.
//
// A prompt is trusted text: it is the one place this project gets to teach a
// model how to use the fleet cheaply, so each one states the token discipline
// in its own body rather than assuming the tool descriptions were read.
type Prompt struct {
	// Name is the wire name, e.g. "investigate_alert".
	Name string
	// Title is the human-facing display name.
	Title string
	// Description is the one-line summary shown in a prompt picker.
	Description string
	// Arguments are the templating arguments.
	Arguments []PromptArgument
}

// PromptRole is the speaker of a prompt message.
type PromptRole string

const (
	// RoleUser marks a message spoken as the user.
	RoleUser PromptRole = "user"
	// RoleAssistant marks a message spoken as the assistant.
	RoleAssistant PromptRole = "assistant"
)

// PromptMessage is one message of a rendered prompt.
type PromptMessage struct {
	// Role is who is speaking.
	Role PromptRole
	// Text is the message body.
	Text string
}

// PromptResult is a rendered prompt.
type PromptResult struct {
	// Description is the rendered summary.
	Description string
	// Messages are the conversation to seed.
	Messages []PromptMessage
}

// PromptFunc renders a prompt from its arguments. Returning an error makes the
// get a protocol error.
type PromptFunc func(ctx context.Context, args map[string]string) (PromptResult, error)

// AddPrompt registers a prompt.
func (s *Server) AddPrompt(p Prompt, h PromptFunc) {
	args := make([]*mcp.PromptArgument, 0, len(p.Arguments))
	for _, a := range p.Arguments {
		args = append(args, &mcp.PromptArgument{
			Name:        a.Name,
			Title:       a.Title,
			Description: a.Description,
			Required:    a.Required,
		})
	}
	s.mcp.AddPrompt(&mcp.Prompt{
		Name:        p.Name,
		Title:       p.Title,
		Description: p.Description,
		Arguments:   args,
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		var in map[string]string
		if req != nil && req.Params != nil {
			in = req.Params.Arguments
		}
		res, err := h(ctx, in)
		if err != nil {
			return nil, err
		}
		msgs := make([]*mcp.PromptMessage, 0, len(res.Messages))
		for _, m := range res.Messages {
			role := mcp.Role(m.Role)
			if role == "" {
				role = mcp.Role(RoleUser)
			}
			msgs = append(msgs, &mcp.PromptMessage{
				Role:    role,
				Content: &mcp.TextContent{Text: m.Text},
			})
		}
		return &mcp.GetPromptResult{Description: res.Description, Messages: msgs}, nil
	})
	s.record(&s.prompts, p.Name)
}
