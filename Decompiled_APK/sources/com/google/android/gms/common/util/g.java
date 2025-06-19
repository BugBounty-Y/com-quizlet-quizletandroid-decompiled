package com.google.android.gms.common.util;

import android.os.StrictMode;

/* loaded from: classes2.dex */
public abstract class g {
    public static StrictMode.VmPolicy.Builder a(StrictMode.VmPolicy.Builder builder) {
        return builder.permitUnsafeIntentLaunch();
    }
}
