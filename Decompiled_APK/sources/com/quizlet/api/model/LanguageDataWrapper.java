package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/* loaded from: classes2.dex */
public class LanguageDataWrapper {
    List<DetectLanguage> detectLanguageList;

    public List<DetectLanguage> getDetectLanguageList() {
        return this.detectLanguageList;
    }

    @JsonProperty("detectLanguage")
    public void setDetectLanguageList(List<DetectLanguage> list) {
        this.detectLanguageList = list;
    }
}
