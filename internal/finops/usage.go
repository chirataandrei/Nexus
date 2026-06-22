// Package finops implementează ruterul de control financiar al Nexus
// Trust Protocol: citește consumul real de tokeni din răspunsurile
// modelelor LLM, îl acumulează per agent/sarcină și aplică bariere "hard"
// (circuit breaking) direct pe fluxul cererilor — înainte ca o nouă
// cerere costisitoare să ajungă la model — în loc de rapoarte de cost
// analizate retrospectiv.
package finops

import "encoding/json"

// openAIUsageEnvelope este forma minimă a câmpului "usage" din
// răspunsurile API OpenAI (chat completions, completions, etc.).
type openAIUsageEnvelope struct {
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// anthropicUsageEnvelope este forma minimă a câmpului "usage" din
// răspunsurile API Anthropic (Messages API).
type anthropicUsageEnvelope struct {
	Usage *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ExtractTokens încearcă să citească numărul total de tokeni consumați
// dintr-un corp de răspuns JSON al unui upstream LLM, recunoscând
// formatele OpenAI și Anthropic. Returnează ok=false dacă body nu este
// JSON valid sau nu conține un câmp "usage" recunoscut — ceea ce este
// normal și de așteptat pentru upstream-uri care nu sunt modele LLM
// (ex. instrumente interne), caz în care pur și simplu nu se
// înregistrează niciun cost.
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
