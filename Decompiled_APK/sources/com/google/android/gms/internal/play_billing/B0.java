package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class B0 extends AbstractC3816m0 implements Runnable, InterfaceC3804i0 {
    public final Runnable h;

    public B0(Runnable runnable) {
        runnable.getClass();
        this.h = runnable;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3816m0
    public final String c() {
        return android.support.v4.media.session.a.B("task=[", this.h.toString(), "]");
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            this.h.run();
        } catch (Throwable th) {
            e(th);
            throw th;
        }
    }
}
