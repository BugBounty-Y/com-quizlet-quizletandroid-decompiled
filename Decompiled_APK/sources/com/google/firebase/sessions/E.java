package com.google.firebase.sessions;

import android.app.Application;
import android.os.Build;
import android.os.Process;
import android.util.Base64;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes2.dex */
public abstract class E {
    public static final String a;
    public static final String b;

    static {
        String strH;
        int i = Build.VERSION.SDK_INT;
        if (i > 33) {
            strH = Process.myProcessName();
            Intrinsics.checkNotNullExpressionValue(strH, "myProcessName()");
        } else if ((i < 28 || (strH = Application.getProcessName()) == null) && (strH = com.google.android.gms.common.util.c.h()) == null) {
            strH = "";
        }
        Intrinsics.checkNotNullParameter(strH, "<this>");
        byte[] bytes = strH.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        String strEncodeToString = Base64.encodeToString(bytes, 10);
        a = android.support.v4.media.session.a.B("firebase_session_", strEncodeToString, "_data");
        b = android.support.v4.media.session.a.B("firebase_session_", strEncodeToString, "_settings");
    }
}
