package com.quizlet.api.model;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class ApiError implements ServerProvidedError {

    @JsonProperty("code")
    protected Integer code;

    @JsonProperty("identifier")
    protected String identifier;

    @JsonProperty("message")
    protected String message;

    @JsonIgnore
    public Integer getCode() {
        return this.code;
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
    public void setCode(Integer num) {
        this.code = num;
    }

    @JsonIgnore
    public void setMessage(String str) {
        this.message = str;
    }

    public String toString() {
        return this.code + "(" + this.identifier + "): " + this.message;
    }
}
