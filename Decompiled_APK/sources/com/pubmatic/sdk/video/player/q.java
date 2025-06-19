package com.pubmatic.sdk.video.player;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public enum q {
    MEDIA_3GPP("video/3gpp"),
    MEDIA_MP4("video/mp4"),
    MEDIA_WEBM("video/webm");

    private final String b;

    q(String str) {
        this.b = str;
    }

    @NonNull
    public static String[] getStringValues() {
        q[] qVarArrValues = values();
        String[] strArr = new String[qVarArrValues.length];
        for (int i = 0; i < qVarArrValues.length; i++) {
            strArr[i] = qVarArrValues[i].getValue();
        }
        return strArr;
    }

    public String getValue() {
        return this.b;
    }
}
