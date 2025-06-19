package com.iab.omid.library.pubmatic.adsession;

import com.comscore.android.id.IdHelperAndroid;
import com.pubmatic.sdk.common.base.c;

/* loaded from: classes2.dex */
public enum Owner {
    NATIVE(c.CREATIVE_TYPE_NATIVE),
    JAVASCRIPT("javascript"),
    NONE(IdHelperAndroid.NO_ID_AVAILABLE);

    private final String owner;

    Owner(String str) {
        this.owner = str;
    }

    @Override // java.lang.Enum
    public String toString() {
        return this.owner;
    }
}
