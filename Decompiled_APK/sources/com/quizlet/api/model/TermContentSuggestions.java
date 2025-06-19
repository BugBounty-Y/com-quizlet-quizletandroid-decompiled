package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
/* loaded from: classes2.dex */
public class TermContentSuggestions {
    public final Parameters parameters;
    public final String requestId;
    public final List<Suggestions> suggestions;

    public static class Parameters {
        public final String defLangCode;
        public final String localTermId;
        public final String prefix;
        public final String word;
        public final String wordLangCode;

        @JsonCreator
        public Parameters(@JsonProperty("word") String str, @JsonProperty("prefix") String str2, @JsonProperty("localTermId") String str3, @JsonProperty("wordLang") String str4, @JsonProperty("defLang") String str5) {
            this.word = str;
            this.prefix = str2;
            this.localTermId = str3;
            this.wordLangCode = str4;
            this.defLangCode = str5;
        }
    }

    public static class Suggestions {
        public final long id;
        public final String text;

        public Suggestions(@JsonProperty("text") String str, @JsonProperty("id") long j) {
            this.text = str;
            this.id = j;
        }
    }

    @JsonCreator
    public TermContentSuggestions(@JsonProperty("requestId") String str, @JsonProperty("parameters") Parameters parameters, @JsonProperty("suggestions") List<Suggestions> list) {
        this.requestId = str;
        this.parameters = parameters;
        this.suggestions = list;
    }
}
