package com.google.android.gms.measurement.internal;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;

/* loaded from: classes2.dex */
public final class X0 implements ServiceConnection, InterfaceC1652b, InterfaceC1653c {
    public volatile boolean a;
    public volatile E b;
    public final /* synthetic */ Y0 c;

    public X0(Y0 y0) {
        this.c = y0;
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void V(int i) {
        Y y = (Y) this.c.b;
        X x = y.j;
        Y.k(x);
        x.a0();
        I i2 = y.i;
        Y.k(i2);
        i2.n.f("Service connection suspended");
        X x2 = y.j;
        Y.k(x2);
        x2.c0(new com.google.android.gms.common.api.internal.w(this, 3));
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void X() {
        X x = ((Y) this.c.b).j;
        Y.k(x);
        x.a0();
        synchronized (this) {
            try {
                com.google.android.gms.common.internal.u.h(this.b);
                InterfaceC3897v interfaceC3897v = (InterfaceC3897v) this.b.m();
                X x2 = ((Y) this.c.b).j;
                Y.k(x2);
                x2.c0(new W0(this, interfaceC3897v, 1));
            } catch (DeadObjectException | IllegalStateException unused) {
                this.b = null;
                this.a = false;
            }
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public final void f0(ConnectionResult connectionResult) {
        Y0 y0 = this.c;
        X x = ((Y) y0.b).j;
        Y.k(x);
        x.a0();
        I i = ((Y) y0.b).i;
        if (i == null || !i.c) {
            i = null;
        }
        if (i != null) {
            i.j.g("Service connection failed", connectionResult);
        }
        synchronized (this) {
            this.a = false;
            this.b = null;
        }
        X x2 = ((Y) this.c.b).j;
        Y.k(x2);
        x2.c0(new A0(4, this, connectionResult));
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        X x = ((Y) this.c.b).j;
        Y.k(x);
        x.a0();
        synchronized (this) {
            if (iBinder == null) {
                this.a = false;
                I i = ((Y) this.c.b).i;
                Y.k(i);
                i.g.f("Service connected with null binder");
                return;
            }
            InterfaceC3897v c3895u = null;
            try {
                String interfaceDescriptor = iBinder.getInterfaceDescriptor();
                if ("com.google.android.gms.measurement.internal.IMeasurementService".equals(interfaceDescriptor)) {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.measurement.internal.IMeasurementService");
                    c3895u = iInterfaceQueryLocalInterface instanceof InterfaceC3897v ? (InterfaceC3897v) iInterfaceQueryLocalInterface : new C3895u(iBinder);
                    I i2 = ((Y) this.c.b).i;
                    Y.k(i2);
                    i2.o.f("Bound to IMeasurementService interface");
                } else {
                    I i3 = ((Y) this.c.b).i;
                    Y.k(i3);
                    i3.g.g("Got binder with a wrong descriptor", interfaceDescriptor);
                }
            } catch (RemoteException unused) {
                I i4 = ((Y) this.c.b).i;
                Y.k(i4);
                i4.g.f("Service connect failed to get IMeasurementService");
            }
            if (c3895u == null) {
                this.a = false;
                try {
                    com.google.android.gms.common.stats.a aVarB = com.google.android.gms.common.stats.a.b();
                    Y0 y0 = this.c;
                    aVarB.c(((Y) y0.b).a, y0.d);
                } catch (IllegalArgumentException unused2) {
                }
            } else {
                X x2 = ((Y) this.c.b).j;
                Y.k(x2);
                x2.c0(new W0(this, c3895u, 0));
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        Y y = (Y) this.c.b;
        X x = y.j;
        Y.k(x);
        x.a0();
        I i = y.i;
        Y.k(i);
        i.n.f("Service disconnected");
        X x2 = y.j;
        Y.k(x2);
        x2.c0(new A0(3, this, componentName));
    }
}
