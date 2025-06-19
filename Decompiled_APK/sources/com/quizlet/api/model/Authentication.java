package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class Authentication {
    private String accessToken;
    private String existingMaskedEmail;
    private String existingProfileImage;
    private boolean existingUserIsPlus;
    private String existingUsername;
    private String oauthState;
    private String reauthToken;
    private boolean shouldSeeUpsell;
    private String state;

    public String getAccessToken() {
        return this.accessToken;
    }

    public String getExistingMaskedEmail() {
        return this.existingMaskedEmail;
    }

    public String getExistingProfileImage() {
        return this.existingProfileImage;
    }

    public String getExistingUsername() {
        return this.existingUsername;
    }

    public String getOauthState() {
        return this.oauthState;
    }

    public String getReauthToken() {
        return this.reauthToken;
    }

    public String getState() {
        return this.state;
    }

    public boolean isExistingUserIsPlus() {
        return this.existingUserIsPlus;
    }

    public boolean isShouldSeeUpsell() {
        return this.shouldSeeUpsell;
    }

    public void setAccessToken(String str) {
        this.accessToken = str;
    }

    public void setExistingMaskedEmail(String str) {
        this.existingMaskedEmail = str;
    }

    public void setExistingProfileImage(String str) {
        this.existingProfileImage = str;
    }

    public void setExistingUserIsPlus(boolean z) {
        this.existingUserIsPlus = z;
    }

    public void setExistingUsername(String str) {
        this.existingUsername = str;
    }

    public void setOauthState(String str) {
        this.oauthState = str;
    }

    public void setReauthToken(String str) {
        this.reauthToken = str;
    }

    public void setShouldSeeUpsell(boolean z) {
        this.shouldSeeUpsell = z;
    }

    public void setState(String str) {
        this.state = str;
    }
}
