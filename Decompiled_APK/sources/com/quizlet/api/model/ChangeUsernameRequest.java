package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class ChangeUsernameRequest {

    @JsonProperty
    protected List<Data> data = new ArrayList();

    @JsonProperty
    protected Authentication authentication = new Authentication();

    public static class Authentication {

        @JsonProperty
        protected String reauthToken;
    }

    public static class Data {

        @JsonProperty
        protected String username;
    }

    public ChangeUsernameRequest(String str, String str2) {
        Data data = new Data();
        data.username = str;
        this.data.add(data);
        this.authentication.reauthToken = str2;
    }
}
