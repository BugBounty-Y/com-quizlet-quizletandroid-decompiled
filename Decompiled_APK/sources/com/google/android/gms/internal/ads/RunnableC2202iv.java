package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.iv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC2202iv implements Runnable {
    public final AbstractC2460ov a;
    public final com.google.common.util.concurrent.e b;

    public RunnableC2202iv(AbstractC2460ov abstractC2460ov, com.google.common.util.concurrent.e eVar) {
        this.a = abstractC2460ov;
        this.b = eVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.a.a != this) {
            return;
        }
        com.google.common.util.concurrent.e eVar = this.b;
        if (AbstractC2674tv.g.z(this.a, this, AbstractC2460ov.i(eVar))) {
            AbstractC2460ov.r(this.a, false);
        }
    }
}
