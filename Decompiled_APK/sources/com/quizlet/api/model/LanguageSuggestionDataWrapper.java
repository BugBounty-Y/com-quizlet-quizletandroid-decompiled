package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/* loaded from: classes2.dex */
public class LanguageSuggestionDataWrapper {
    LanguageSuggestions languages;

    public LanguageSuggestions getSuggestions() {
        return this.languages;
    }

    @JsonProperty("suggestions")
    public void setLangauges(LanguageSuggestions languageSuggestions) {
        this.languages = languageSuggestions;
    }
}
