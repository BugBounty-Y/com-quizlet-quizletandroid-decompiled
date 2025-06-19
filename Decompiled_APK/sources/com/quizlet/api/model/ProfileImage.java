package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/* loaded from: classes2.dex */
public class ProfileImage {

    @JsonProperty("_url")
    private String dUrl;

    @JsonProperty("id")
    private String id;

    public ProfileImage() {
    }

    public String getId() {
        return this.id;
    }

    public String getUrl() {
        return this.dUrl;
    }

    public ProfileImage(String str, String str2) {
        this.id = str;
        this.dUrl = str2;
    }
}
