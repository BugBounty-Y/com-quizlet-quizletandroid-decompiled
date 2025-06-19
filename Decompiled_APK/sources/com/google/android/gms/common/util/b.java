package com.google.android.gms.common.util;

import android.os.SystemClock;

/* loaded from: classes2.dex */
public final class b implements a {
    public static final b a = new b();

    @Override // com.google.android.gms.common.util.a
    public final long currentTimeMillis() {
        return System.currentTimeMillis();
    }

    @Override // com.google.android.gms.common.util.a
    public final long elapsedRealtime() {
        return SystemClock.elapsedRealtime();
    }
}
