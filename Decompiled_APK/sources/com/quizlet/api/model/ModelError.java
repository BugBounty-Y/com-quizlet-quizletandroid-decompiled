package com.quizlet.api.model;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class ModelError implements ServerProvidedError {

    @JsonProperty("code")
    protected Integer code;

    @JsonProperty("identifier")
    protected String identifier;

    @JsonProperty("message")
    protected String message;

    @JsonProperty("models")
    protected ModelWrapper modelWrapper;

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

    @JsonIgnore
    public ModelWrapper getModelWrapper() {
        return this.modelWrapper;
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
    public void setIdentifier(String str) {
        this.identifier = str;
    }

    @JsonIgnore
    public void setMessage(String str) {
        this.message = str;
    }

    @JsonIgnore
    public void setModelWrapper(ModelWrapper modelWrapper) {
        this.modelWrapper = modelWrapper;
    }

    public String toString() {
        return this.code + "(" + this.identifier + "): " + this.message;
    }
}
