package com.google.android.gms.internal.ads;

import android.content.ComponentName;
import android.content.Context;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class F7 extends androidx.browser.customtabs.m {
    public final AtomicBoolean b = new AtomicBoolean(false);
    public Context c;
    public Hk d;
    public androidx.work.impl.model.n e;
    public androidx.browser.customtabs.l f;

    @Override // androidx.browser.customtabs.m
    public final void a(ComponentName componentName, androidx.browser.customtabs.l lVar) {
        this.f = lVar;
        lVar.d();
        this.e = lVar.c(new E7(this));
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        this.f = null;
        this.e = null;
    }
}
