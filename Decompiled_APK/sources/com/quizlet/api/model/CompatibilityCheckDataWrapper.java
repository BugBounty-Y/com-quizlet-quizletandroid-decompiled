package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/* loaded from: classes2.dex */
public class CompatibilityCheckDataWrapper {
    CompatibilityCheck compatibilityCheck;

    public CompatibilityCheck getCompatibilityCheck() {
        return this.compatibilityCheck;
    }

    @JsonProperty("compatibilityCheck")
    public void setCompatibilityCheck(CompatibilityCheck compatibilityCheck) {
        this.compatibilityCheck = compatibilityCheck;
    }
}
