package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/* loaded from: classes2.dex */
public class FeaturesDataWrapper {
    Map<String, Boolean> features;

    public Map<String, Boolean> getFeatures() {
        return this.features;
    }

    @JsonProperty("features")
    public void setFeatures(Map<String, Boolean> map) {
        this.features = map;
    }
}
