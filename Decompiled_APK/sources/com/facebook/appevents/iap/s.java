package com.facebook.appevents.iap;

import com.comscore.android.id.IdHelperAndroid;

/* loaded from: classes.dex */
public enum s {
    NONE(IdHelperAndroid.NO_ID_AVAILABLE),
    V1("Android-GPBL-V1"),
    V2_V4("Android-GPBL-V2-V4"),
    V5_V7("Android-GPBL-V5-V7");

    public final String a;

    s(String str) {
        this.a = str;
    }
}
