package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/* loaded from: classes2.dex */
public class UsernameDataWrapper {
    public final CheckUsername checkUsername;

    public static class CheckUsername {
        public final boolean success;
        public final List<String> suggestions;

        public CheckUsername(@JsonProperty("success") boolean z, @JsonProperty("suggestions") List<String> list) {
            this.success = z;
            this.suggestions = list;
        }
    }

    public UsernameDataWrapper(@JsonProperty("checkUsername") CheckUsername checkUsername) {
        this.checkUsername = checkUsername;
    }
}
