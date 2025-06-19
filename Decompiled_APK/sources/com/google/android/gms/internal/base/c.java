package com.google.android.gms.internal.base;

import android.os.Build;

/* loaded from: classes2.dex */
public abstract class c {
    public static final int a;

    static {
        a = Build.VERSION.SDK_INT >= 31 ? 33554432 : 0;
    }
}
