package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class DataWrapper {
    Authentication authentication;

    public Authentication getAuthentication() {
        return this.authentication;
    }

    @JsonProperty("authentication")
    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }
}
