package com.google.android.gms.measurement.internal;

import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class T0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzr b;
    public final /* synthetic */ Y0 c;

    public /* synthetic */ T0(Y0 y0, zzr zzrVar, int i) {
        this.a = i;
        this.b = zzrVar;
        this.c = y0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Y0 y0 = this.c;
                InterfaceC3897v interfaceC3897v = y0.e;
                Y y = (Y) y0.b;
                if (interfaceC3897v != null) {
                    try {
                        interfaceC3897v.w0(this.b);
                    } catch (RemoteException e) {
                        I i = y.i;
                        Y.k(i);
                        i.g.g("Failed to reset data on the service: remote exception", e);
                    }
                    y0.h0();
                    break;
                } else {
                    I i2 = y.i;
                    Y.k(i2);
                    i2.g.f("Failed to reset data on the service: not connected to service");
                    break;
                }
            case 1:
                Y0 y02 = this.c;
                InterfaceC3897v interfaceC3897v2 = y02.e;
                Y y2 = (Y) y02.b;
                if (interfaceC3897v2 == null) {
                    I i3 = y2.i;
                    Y.k(i3);
                    i3.j.f("Failed to send app backgrounded");
                    break;
                } else {
                    try {
                        interfaceC3897v2.C3(this.b);
                        y02.h0();
                        break;
                    } catch (RemoteException e2) {
                        I i4 = y2.i;
                        Y.k(i4);
                        i4.g.g("Failed to send app backgrounded to the service", e2);
                        return;
                    }
                }
            default:
                Y0 y03 = this.c;
                InterfaceC3897v interfaceC3897v3 = y03.e;
                Y y3 = (Y) y03.b;
                if (interfaceC3897v3 == null) {
                    I i5 = y3.i;
                    Y.k(i5);
                    i5.g.f("Failed to send measurementEnabled to service");
                    break;
                } else {
                    try {
                        interfaceC3897v3.X1(this.b);
                        y03.h0();
                        break;
                    } catch (RemoteException e3) {
                        I i6 = y3.i;
                        Y.k(i6);
                        i6.g.g("Failed to send measurementEnabled to the service", e3);
                    }
                }
        }
    }
}
