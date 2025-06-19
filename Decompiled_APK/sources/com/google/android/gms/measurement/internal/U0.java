package com.google.android.gms.measurement.internal;

import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class U0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzr b;
    public final /* synthetic */ Y0 c;

    public /* synthetic */ U0(Y0 y0, zzr zzrVar, int i) {
        this.a = i;
        this.b = zzrVar;
        this.c = y0;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        switch (this.a) {
            case 0:
                Y0 y0 = this.c;
                InterfaceC3897v interfaceC3897v = y0.e;
                Y y = (Y) y0.b;
                if (interfaceC3897v == null) {
                    I i = y.i;
                    Y.k(i);
                    i.g.f("Discarding data. Failed to send app launch");
                    break;
                } else {
                    try {
                        zzr zzrVar = this.b;
                        C3864e c3864e = y.g;
                        C3891s c3891s = AbstractC3893t.l1;
                        if (c3864e.f0(null, c3891s)) {
                            y0.Y(interfaceC3897v, null, zzrVar);
                        }
                        interfaceC3897v.h2(zzrVar);
                        y.o().X();
                        y.g.f0(null, c3891s);
                        y0.Y(interfaceC3897v, null, zzrVar);
                        y0.h0();
                        break;
                    } catch (RemoteException e) {
                        I i2 = y.i;
                        Y.k(i2);
                        i2.g.g("Failed to send app launch to the service", e);
                        return;
                    }
                }
            default:
                Y0 y02 = this.c;
                InterfaceC3897v interfaceC3897v2 = y02.e;
                Y y2 = (Y) y02.b;
                if (interfaceC3897v2 == null) {
                    I i3 = y2.i;
                    Y.k(i3);
                    i3.g.f("Failed to send consent settings to service");
                    break;
                } else {
                    try {
                        interfaceC3897v2.R3(this.b);
                        y02.h0();
                        break;
                    } catch (RemoteException e2) {
                        I i4 = y2.i;
                        Y.k(i4);
                        i4.g.g("Failed to send consent settings to the service", e2);
                    }
                }
        }
    }
}
