package com.google.android.gms.internal.ads;

import com.comscore.android.id.IdHelperAndroid;

/* loaded from: classes2.dex */
public enum Mr {
    NATIVE(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE),
    JAVASCRIPT("javascript"),
    NONE(IdHelperAndroid.NO_ID_AVAILABLE);

    public final String a;

    Mr(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
