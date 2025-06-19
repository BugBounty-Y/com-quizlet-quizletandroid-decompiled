package com.google.android.gms.measurement.internal;

import android.os.RemoteException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Q0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AtomicReference b;
    public final /* synthetic */ zzr c;
    public final /* synthetic */ Y0 d;

    public /* synthetic */ Q0(Y0 y0, AtomicReference atomicReference, zzr zzrVar, int i) {
        this.a = i;
        this.b = atomicReference;
        this.c = zzrVar;
        this.d = y0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        AtomicReference atomicReference;
        Y0 y0;
        InterfaceC3897v interfaceC3897v;
        AtomicReference atomicReference2;
        Y0 y02;
        Y y;
        O o;
        switch (this.a) {
            case 0:
                AtomicReference atomicReference3 = this.b;
                synchronized (atomicReference3) {
                    try {
                        try {
                            y0 = this.d;
                            interfaceC3897v = y0.e;
                        } catch (RemoteException e) {
                            I i = ((Y) this.d.b).i;
                            Y.k(i);
                            i.g.g("Failed to get all user properties; remote exception", e);
                            atomicReference = this.b;
                        }
                        if (interfaceC3897v == null) {
                            I i2 = ((Y) y0.b).i;
                            Y.k(i2);
                            i2.g.f("Failed to get all user properties; not connected to service");
                            atomicReference3.notify();
                            return;
                        }
                        atomicReference3.set(interfaceC3897v.N0(this.c, true));
                        y0.h0();
                        atomicReference = this.b;
                        atomicReference.notify();
                        return;
                    } finally {
                    }
                }
            default:
                AtomicReference atomicReference4 = this.b;
                synchronized (atomicReference4) {
                    try {
                        try {
                            y02 = this.d;
                            y = (Y) y02.b;
                            o = y.h;
                            Y.h(o);
                        } catch (RemoteException e2) {
                            I i3 = ((Y) this.d.b).i;
                            Y.k(i3);
                            i3.g.g("Failed to get app instance id", e2);
                            atomicReference2 = this.b;
                        }
                        if (o.Z().k(EnumC3879l0.ANALYTICS_STORAGE)) {
                            InterfaceC3897v interfaceC3897v2 = y02.e;
                            if (interfaceC3897v2 != null) {
                                atomicReference4.set(interfaceC3897v2.u2(this.c));
                                String str = (String) atomicReference4.get();
                                if (str != null) {
                                    D0 d0 = ((Y) y02.b).p;
                                    Y.j(d0);
                                    d0.h.set(str);
                                    O o2 = y.h;
                                    Y.h(o2);
                                    o2.i.m(str);
                                }
                                y02.h0();
                                atomicReference2 = this.b;
                                atomicReference2.notify();
                                return;
                            }
                            I i4 = y.i;
                            Y.k(i4);
                            i4.g.f("Failed to get app instance id");
                            atomicReference4.notify();
                        } else {
                            I i5 = y.i;
                            Y.k(i5);
                            i5.l.f("Analytics storage consent denied; will not get app instance id");
                            D0 d02 = ((Y) y02.b).p;
                            Y.j(d02);
                            d02.h.set(null);
                            O o3 = y.h;
                            Y.h(o3);
                            o3.i.m(null);
                            atomicReference4.set(null);
                            atomicReference4.notify();
                        }
                        return;
                    } finally {
                    }
                }
        }
    }
}
