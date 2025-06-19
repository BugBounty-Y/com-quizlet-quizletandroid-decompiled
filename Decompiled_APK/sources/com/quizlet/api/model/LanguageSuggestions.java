package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class LanguageSuggestions {
    public static final double CONFIDENCE_THRESHOLD = 0.99d;
    private List<Language> languages;
    private Parameters parameters;
    private String requestId;

    public static class Language {
        private Double confidence;
        private String languageCode;

        public Double getConfidence() {
            return this.confidence;
        }

        @JsonProperty("language_code")
        public String getLanguageCode() {
            return this.languageCode;
        }

        public void setConfidence(Double d) {
            this.confidence = d;
        }

        @JsonProperty("language_code")
        public void setLanguageCode(String str) {
            this.languageCode = str;
        }
    }

    public static class Parameters {
        private Long localSetId;
        private List<String> strings;

        public Long getLocalSetId() {
            return this.localSetId;
        }

        public List<String> getStrings() {
            return this.strings;
        }

        public void setLocalSetId(Long l) {
            this.localSetId = l;
        }

        public void setStrings(List<String> list) {
            this.strings = list;
        }
    }

    public List<Language> getLanguages() {
        return this.languages;
    }

    public Parameters getParameters() {
        return this.parameters;
    }

    public String getRequestId() {
        return this.requestId;
    }

    public void setLanguages(List<Language> list) {
        this.languages = list;
    }

    public void setParameters(Parameters parameters) {
        this.parameters = parameters;
    }

    public void setRequestId(String str) {
        this.requestId = str;
    }
}
