// Package finops implements Nexus Trust Protocol's financial control
// router: it reads the real token consumption from LLM model responses,
// accumulates it per agent/task, and applies "hard" barriers (circuit
// breaking) directly on the request path — before a new, costly request
// reaches the model — instead of retrospectively analyzed cost reports.
package finops

import "encoding/json"

// openAIUsageEnvelope is the minimal shape of the "usage" field in
// OpenAI API responses (chat completions, completions, etc.).
type openAIUsageEnvelope struct {
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// anthropicUsageEnvelope is the minimal shape of the "usage" field in
// Anthropic API responses (Messages API).
type anthropicUsageEnvelope struct {
	Usage *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ExtractTokens attempts to read the total number of tokens consumed
// from an LLM upstream's JSON response body, recognizing the OpenAI and
// Anthropic formats. Returns ok=false if body isn't valid JSON or
// doesn't contain a recognized "usage" field — which is normal and
// expected for upstreams that aren't LLM models (e.g. internal tools),
// in which case simply no cost is recorded.
func ExtractTokens(body []byte) (int, bool) {
	var oa openAIUsageEnvelope
	if err := json.Unmarshal(body, &oa); err == nil && oa.Usage != nil {
		if oa.Usage.TotalTokens > 0 {
			return oa.Usage.TotalTokens, true
		}
		if sum := oa.Usage.PromptTokens + oa.Usage.CompletionTokens; sum > 0 {
			return sum, true
		}
	}

	var an anthropicUsageEnvelope
	if err := json.Unmarshal(body, &an); err == nil && an.Usage != nil {
		if sum := an.Usage.InputTokens + an.Usage.OutputTokens; sum > 0 {
			return sum, true
		}
	}

	return 0, false
}
