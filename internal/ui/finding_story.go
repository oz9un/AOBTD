package ui

import (
	"regexp"
	"strings"
)

type findingStory struct {
	Kind      string             `json:"kind"`
	Title     string             `json:"title"`
	Lead      string             `json:"lead"`
	Rationale string             `json:"rationale,omitempty"`
	Steps     []findingStoryStep `json:"steps"`
	Takeaway  string             `json:"takeaway"`
}

type findingStoryStep struct {
	Label string `json:"label"`
	Text  string `json:"text"`
	Tone  string `json:"tone,omitempty"`
}

var (
	findingStoryEvidenceBullet = regexp.MustCompile(`(?m)^-\s*([^:\n]+):\s*(.+)$`)
	findingStoryRationale      = regexp.MustCompile(`(?m)^Rationale:\s*(.+)$`)
)

func findingStoryFor(vulnType, evidence, description string) *findingStory {
	if !strings.EqualFold(strings.TrimSpace(vulnType), "bola") {
		return nil
	}
	if !strings.Contains(evidence, "Two-persona BOLA confirmation") {
		return nil
	}

	bullets := extractFindingStoryBullets(evidence)
	steps := make([]findingStoryStep, 0, 4)
	appendBulletStep := func(key, label, tone string) {
		if text := bullets[key]; text != "" {
			steps = append(steps, findingStoryStep{Label: label, Text: text, Tone: tone})
		}
	}
	appendBulletStep("Positive control B→B", "B can read B-owned object", "control")
	appendBulletStep("Positive control A→A", "A can read A-owned object", "control")
	appendBulletStep("Anonymous control → B", "Anonymous boundary checked", "boundary")
	appendBulletStep("Attack A→B", "A reads B-owned object", "attack")

	if len(steps) == 0 {
		return nil
	}

	rationale := extractFindingStoryRationale(evidence)
	if rationale == "" {
		rationale = extractFindingStoryRationale(description)
	}

	return &findingStory{
		Kind:      "ownership_proof",
		Title:     "Ownership proof trail",
		Lead:      "AOBTD established which persona owned which object, checked that the object was not simply public, then reused persona A's authenticated session against persona B's object.",
		Rationale: rationale,
		Steps:     steps,
		Takeaway:  "Confirmed only because the cross-owner request was accessible and the response still carried persona B's owner marker.",
	}
}

func extractFindingStoryBullets(evidence string) map[string]string {
	out := map[string]string{}
	for _, match := range findingStoryEvidenceBullet.FindAllStringSubmatch(evidence, -1) {
		if len(match) != 3 {
			continue
		}
		label := strings.TrimSpace(match[1])
		text := strings.TrimSpace(match[2])
		text = strings.TrimSuffix(text, ".")
		out[label] = text
	}
	return out
}

func extractFindingStoryRationale(text string) string {
	match := findingStoryRationale.FindStringSubmatch(text)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}
