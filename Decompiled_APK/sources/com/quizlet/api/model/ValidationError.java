package com.quizlet.api.model;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class ValidationError implements ServerProvidedError {

    @JsonProperty("field")
    protected String field;

    @JsonProperty("identifier")
    protected String identifier;

    @JsonProperty("message")
    protected String message;

    @JsonIgnore
    public String getField() {
        return this.field;
    }

    @Override // com.quizlet.api.model.ServerProvidedError
    @NonNull
    @JsonIgnore
    public String getIdentifier() {
        return this.identifier;
    }

    @Override // com.quizlet.api.model.ServerProvidedError
    @NonNull
    @JsonIgnore
    public String getServerMessage() {
        return this.message;
    }

    @JsonIgnore
    public void setField(String str) {
        this.field = str;
    }

    @JsonIgnore
    public void setIdentifier(String str) {
        this.identifier = str;
    }

    @JsonIgnore
    public void setMessage(String str) {
        this.message = str;
    }
}
