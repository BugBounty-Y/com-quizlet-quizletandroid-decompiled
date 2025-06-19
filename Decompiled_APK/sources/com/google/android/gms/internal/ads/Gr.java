package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public enum Gr {
    HTML("html"),
    /* JADX INFO: Fake field, exist only in values array */
    NATIVE(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE),
    JAVASCRIPT("javascript");

    public final String a;

    Gr(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
