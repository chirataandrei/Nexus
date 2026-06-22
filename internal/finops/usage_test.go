package finops

import "testing"

func TestExtractTokens_OpenAIShape_TotalTokens(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":120,"completion_tokens":80,"total_tokens":200}}`)
	tokens, ok := ExtractTokens(body)
	if !ok {
		t.Fatal("ExtractTokens ar trebui să recunoască formatul OpenAI")
	}
	if tokens != 200 {
		t.Errorf("tokens = %d, vroiam 200", tokens)
	}
}

func TestExtractTokens_OpenAIShape_NoTotalField(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":50,"completion_tokens":30}}`)
	tokens, ok := ExtractTokens(body)
	if !ok || tokens != 80 {
		t.Fatalf("tokens=%d ok=%v, vroiam 80/true", tokens, ok)
	}
}

func TestExtractTokens_AnthropicShape(t *testing.T) {
	body := []byte(`{"id":"msg_1","usage":{"input_tokens":300,"output_tokens":150}}`)
	tokens, ok := ExtractTokens(body)
	if !ok || tokens != 450 {
		t.Fatalf("tokens=%d ok=%v, vroiam 450/true", tokens, ok)
	}
}

func TestExtractTokens_UnknownShape(t *testing.T) {
	body := []byte(`{"status":"ok","data":[1,2,3]}`)
	if _, ok := ExtractTokens(body); ok {
		t.Error("ExtractTokens nu ar trebui să găsească usage într-un răspuns fără acel câmp")
	}
}

func TestExtractTokens_InvalidJSON(t *testing.T) {
	if _, ok := ExtractTokens([]byte("nu e json")); ok {
		t.Error("ExtractTokens ar trebui să returneze ok=false pentru JSON invalid")
	}
}

func TestExtractTokens_EmptyBody(t *testing.T) {
	if _, ok := ExtractTokens(nil); ok {
		t.Error("ExtractTokens ar trebui să returneze ok=false pentru corp gol")
	}
}
