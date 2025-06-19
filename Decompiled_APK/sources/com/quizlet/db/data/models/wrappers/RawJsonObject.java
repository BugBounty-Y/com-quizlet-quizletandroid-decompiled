package com.quizlet.db.data.models.wrappers;

import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class RawJsonObject {
    private final String value;

    public RawJsonObject(String str) {
        this.value = str;
    }

    public final String getValue() {
        return this.value;
    }
}
