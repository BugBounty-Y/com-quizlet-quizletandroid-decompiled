package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public enum Ir {
    DEFINED_BY_JAVASCRIPT("definedByJavaScript"),
    HTML_DISPLAY("htmlDisplay"),
    NATIVE_DISPLAY("nativeDisplay"),
    VIDEO(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO),
    /* JADX INFO: Fake field, exist only in values array */
    AUDIO("audio");

    public final String a;

    Ir(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
