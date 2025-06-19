package com.iab.omid.library.pubmatic.adsession;

import com.pubmatic.sdk.common.base.c;

/* loaded from: classes2.dex */
public enum ErrorType {
    GENERIC("generic"),
    VIDEO(c.CREATIVE_TYPE_VIDEO);

    private final String errorType;

    ErrorType(String str) {
        this.errorType = str;
    }

    @Override // java.lang.Enum
    public String toString() {
        return this.errorType;
    }
}
