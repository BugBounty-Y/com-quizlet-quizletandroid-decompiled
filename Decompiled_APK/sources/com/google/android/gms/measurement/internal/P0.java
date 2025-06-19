package com.google.android.gms.measurement.internal;

import android.os.RemoteException;

/* loaded from: classes2.dex */
public final /* synthetic */ class P0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Y0 b;

    public /* synthetic */ P0(Y0 y0, int i) {
        this.a = i;
        this.b = y0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Y0 y0 = this.b;
                InterfaceC3897v interfaceC3897v = y0.e;
                Y y = (Y) y0.b;
                if (interfaceC3897v == null) {
                    I i = y.i;
                    Y.k(i);
                    i.g.f("Failed to send storage consent settings to service");
                    break;
                } else {
                    try {
                        interfaceC3897v.k3(y0.f0(false));
                        y0.h0();
                        break;
                    } catch (RemoteException e) {
                        I i2 = y.i;
                        Y.k(i2);
                        i2.g.g("Failed to send storage consent settings to the service", e);
                        return;
                    }
                }
            case 1:
                Y0 y02 = this.b;
                InterfaceC3897v interfaceC3897v2 = y02.e;
                Y y2 = (Y) y02.b;
                if (interfaceC3897v2 == null) {
                    I i3 = y2.i;
                    Y.k(i3);
                    i3.g.f("Failed to send Dma consent settings to service");
                    break;
                } else {
                    try {
                        interfaceC3897v2.C1(y02.f0(false));
                        y02.h0();
                        break;
                    } catch (RemoteException e2) {
                        I i4 = y2.i;
                        Y.k(i4);
                        i4.g.g("Failed to send Dma consent settings to the service", e2);
                        return;
                    }
                }
            default:
                this.b.V();
                break;
        }
    }
}
