package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC3798g0 implements Runnable {
    public final AbstractC3816m0 a;
    public final InterfaceFutureC3845w0 b;

    public RunnableC3798g0(AbstractC3816m0 abstractC3816m0, InterfaceFutureC3845w0 interfaceFutureC3845w0) {
        this.a = abstractC3816m0;
        this.b = interfaceFutureC3845w0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.a.a != this) {
            return;
        }
        InterfaceFutureC3845w0 interfaceFutureC3845w0 = this.b;
        if (AbstractC3816m0.f.E(this.a, this, AbstractC3816m0.f(interfaceFutureC3845w0))) {
            AbstractC3816m0.i(this.a);
        }
    }
}
