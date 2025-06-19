package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.bw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC1899bw extends AbstractC2417nv implements Runnable {
    public final Runnable h;

    public RunnableC1899bw(Runnable runnable) {
        runnable.getClass();
        this.h = runnable;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        return android.support.v4.media.session.a.B("task=[", this.h.toString(), "]");
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            this.h.run();
        } catch (Throwable th) {
            h(th);
            throw th;
        }
    }
}
