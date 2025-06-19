package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.s0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC3833s0 implements Runnable {
    public final InterfaceFutureC3845w0 a;
    public final com.google.android.gms.cloudmessaging.k b;

    public RunnableC3833s0(InterfaceFutureC3845w0 interfaceFutureC3845w0, com.google.android.gms.cloudmessaging.k kVar) {
        this.a = interfaceFutureC3845w0;
        this.b = kVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:9:0x001c  */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() {
        /*
            r5 = this;
            com.google.android.gms.internal.play_billing.w0 r0 = r5.a
            boolean r1 = r0 instanceof com.google.android.gms.internal.play_billing.H0
            com.google.android.gms.cloudmessaging.k r2 = r5.b
            if (r1 == 0) goto L24
            r1 = r0
            com.google.android.gms.internal.play_billing.H0 r1 = (com.google.android.gms.internal.play_billing.H0) r1
            com.google.android.gms.internal.play_billing.m0 r1 = (com.google.android.gms.internal.play_billing.AbstractC3816m0) r1
            boolean r3 = r1 instanceof com.google.android.gms.internal.play_billing.InterfaceC3804i0
            if (r3 == 0) goto L1c
            java.lang.Object r1 = r1.a
            boolean r3 = r1 instanceof com.google.android.gms.internal.play_billing.C3789d0
            if (r3 == 0) goto L1c
            com.google.android.gms.internal.play_billing.d0 r1 = (com.google.android.gms.internal.play_billing.C3789d0) r1
            java.lang.Throwable r1 = r1.a
            goto L1d
        L1c:
            r1 = 0
        L1d:
            if (r1 != 0) goto L20
            goto L24
        L20:
            r2.n(r1)
            return
        L24:
            boolean r1 = r0.isDone()     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            java.lang.String r3 = "Future was expected to be done: %s"
            if (r1 == 0) goto L7d
            r1 = 0
        L2d:
            java.lang.Object r0 = r0.get()     // Catch: java.lang.Throwable -> L6f java.lang.InterruptedException -> L7b
            if (r1 == 0) goto L3f
            java.lang.Thread r1 = java.lang.Thread.currentThread()     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            r1.interrupt()     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            goto L3f
        L3b:
            r0 = move-exception
            goto L8b
        L3d:
            r0 = move-exception
            goto L8f
        L3f:
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r1 = r0.intValue()
            if (r1 <= 0) goto L67
            int r0 = r0.intValue()
            java.lang.Object r1 = r2.e
            com.android.billingclient.api.v r1 = (com.android.billingclient.api.v) r1
            int r3 = r2.b
            r1.getClass()
            java.lang.String r4 = "Billing override value was set by a license tester."
            com.android.billingclient.api.e r0 = com.android.billingclient.api.A.a(r0, r4)
            r4 = 105(0x69, float:1.47E-43)
            r1.F(r4, r3, r0)
            java.lang.Object r1 = r2.c
            java.util.function.Consumer r1 = (java.util.function.Consumer) r1
            r1.accept(r0)
            goto L6e
        L67:
            java.lang.Object r0 = r2.d
            java.lang.Runnable r0 = (java.lang.Runnable) r0
            r0.run()
        L6e:
            return
        L6f:
            r0 = move-exception
            if (r1 != 0) goto L73
            goto L7a
        L73:
            java.lang.Thread r1 = java.lang.Thread.currentThread()     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            r1.interrupt()     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
        L7a:
            throw r0     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
        L7b:
            r1 = 1
            goto L2d
        L7d:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            java.lang.Object[] r0 = new java.lang.Object[]{r0}     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            java.lang.String r0 = com.google.android.gms.internal.play_billing.Z0.g(r3, r0)     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            r1.<init>(r0)     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
            throw r1     // Catch: java.lang.Throwable -> L3b java.util.concurrent.ExecutionException -> L3d
        L8b:
            r2.n(r0)
            return
        L8f:
            java.lang.Throwable r0 = r0.getCause()
            r2.n(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.RunnableC3833s0.run():void");
    }

    public final String toString() {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(RunnableC3833s0.class.getSimpleName(), 7);
        C3803i c3803i = new C3803i();
        ((C3803i) fVar.d).b = c3803i;
        fVar.d = c3803i;
        c3803i.a = this.b;
        return fVar.toString();
    }
}
