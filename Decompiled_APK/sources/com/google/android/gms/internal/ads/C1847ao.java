package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.Looper;

/* renamed from: com.google.android.gms.internal.ads.ao, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1847ao {
    public static final C1847ao a = new C1847ao();

    public final Bo a(Looper looper, Handler.Callback callback) {
        return new Bo(new Handler(looper, callback));
    }
}
