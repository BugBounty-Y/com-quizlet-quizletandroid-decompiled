package com.google.android.gms.internal.ads;

import java.util.concurrent.Callable;
import java.util.concurrent.RunnableFuture;

/* renamed from: com.google.android.gms.internal.ads.hw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableFutureC2161hw extends Mv implements RunnableFuture {
    public volatile Vv h;

    public RunnableFutureC2161hw(Callable callable) {
        this.h = new C2117gw(this, callable);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        Vv vv = this.h;
        return vv != null ? android.support.v4.media.session.a.B("task=[", vv.toString(), "]") : super.e();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void f() {
        Vv vv;
        if (p() && (vv = this.h) != null) {
            vv.g();
        }
        this.h = null;
    }

    @Override // java.util.concurrent.RunnableFuture, java.lang.Runnable
    public final void run() {
        Vv vv = this.h;
        if (vv != null) {
            vv.run();
        }
        this.h = null;
    }
}
