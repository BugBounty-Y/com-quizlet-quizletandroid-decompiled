package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.eg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2013eg implements E5 {
    public final InterfaceC2529qe a;
    public final Executor b;
    public final AtomicReference c = new AtomicReference();

    public C2013eg(InterfaceC2529qe interfaceC2529qe, Executor executor) {
        this.a = interfaceC2529qe;
        this.b = executor;
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final synchronized void R0(D5 d5) {
        InterfaceC2529qe interfaceC2529qe = this.a;
        if (interfaceC2529qe != null) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Bc)).booleanValue()) {
                if (d5.j) {
                    AtomicReference atomicReference = this.c;
                    Boolean bool = Boolean.TRUE;
                    if (!bool.equals(atomicReference.getAndSet(bool))) {
                        this.b.execute(new RunnableC1970dg(interfaceC2529qe, 0));
                    }
                } else {
                    AtomicReference atomicReference2 = this.c;
                    Boolean bool2 = Boolean.FALSE;
                    if (!bool2.equals(atomicReference2.getAndSet(bool2))) {
                        this.b.execute(new RunnableC1970dg(interfaceC2529qe, 1));
                    }
                }
            }
        }
    }
}
