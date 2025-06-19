package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/* loaded from: classes2.dex */
public class SuggestionsDataWrapper {
    TermContentSuggestions suggestions;

    public TermContentSuggestions getSuggestions() {
        return this.suggestions;
    }

    @JsonProperty("suggestions")
    public void setSuggestions(TermContentSuggestions termContentSuggestions) {
        this.suggestions = termContentSuggestions;
    }
}
