package com.google.android.gms.internal.cloudmessaging;

import android.os.Build;

/* loaded from: classes2.dex */
public abstract class a {
    public static final int a;

    static {
        a = Build.VERSION.SDK_INT >= 31 ? 33554432 : 0;
    }
}
