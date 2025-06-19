package com.iab.omid.library.amazon.adsession;

/* loaded from: classes2.dex */
public enum e {
    HTML("html"),
    /* JADX INFO: Fake field, exist only in values array */
    NATIVE(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE),
    JAVASCRIPT("javascript");

    public final String a;

    e(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
