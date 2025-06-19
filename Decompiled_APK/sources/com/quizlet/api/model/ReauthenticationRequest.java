package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;

/* loaded from: classes2.dex */
public class ReauthenticationRequest {

    @JsonProperty("authentication")
    public Authentication authentication;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Authentication {

        @JsonProperty("fbToken")
        public String fbToken;

        @JsonProperty("googleToken")
        public String googleToken;

        @JsonProperty(DBStudySetFields.Names.PASSWORD)
        public String password;

        public /* synthetic */ Authentication(int i) {
            this();
        }

        private Authentication() {
        }
    }

    public ReauthenticationRequest(String str, String str2, String str3) {
        Authentication authentication = new Authentication(0);
        this.authentication = authentication;
        authentication.password = str;
        authentication.fbToken = str2;
        authentication.googleToken = str3;
    }
}
