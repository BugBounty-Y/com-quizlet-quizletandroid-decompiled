package com.google.android.gms.internal.gtm;

import android.os.Handler;
import android.os.Looper;

/* loaded from: classes2.dex */
public class zzfy extends Handler {
    public zzfy() {
        Looper.getMainLooper();
    }

    public zzfy(Looper looper) {
        super(looper);
        Looper.getMainLooper();
    }

    public zzfy(Looper looper, Handler.Callback callback) {
        super(looper, callback);
        Looper.getMainLooper();
    }
}
