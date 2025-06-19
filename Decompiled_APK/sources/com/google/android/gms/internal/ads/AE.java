package com.google.android.gms.internal.ads;

import android.os.Build;

/* loaded from: classes2.dex */
public abstract class AE {
    public static final /* synthetic */ int a = 0;

    static {
        if ("Amazon".equals(Build.MANUFACTURER)) {
            String str = Build.MODEL;
            if ("AFTM".equals(str)) {
                return;
            }
            "AFTB".equals(str);
        }
    }
}
