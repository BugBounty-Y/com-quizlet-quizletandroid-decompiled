package com.iab.omid.library.amazon.adsession;

/* loaded from: classes2.dex */
public enum f {
    DEFINED_BY_JAVASCRIPT("definedByJavaScript"),
    HTML_DISPLAY("htmlDisplay"),
    /* JADX INFO: Fake field, exist only in values array */
    NATIVE_DISPLAY("nativeDisplay"),
    /* JADX INFO: Fake field, exist only in values array */
    VIDEO(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO),
    /* JADX INFO: Fake field, exist only in values array */
    AUDIO("audio");

    public final String a;

    f(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
