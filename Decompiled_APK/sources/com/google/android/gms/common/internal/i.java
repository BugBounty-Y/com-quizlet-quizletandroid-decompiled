package com.google.android.gms.common.internal;

import com.google.android.gms.common.ConnectionResult;

/* loaded from: classes2.dex */
public final class i implements InterfaceC1654d, InterfaceC1652b, InterfaceC1653c {
    public static i b;
    public static final RootTelemetryConfiguration c = new RootTelemetryConfiguration(0, 0, 0, false, false);
    public Object a;

    public /* synthetic */ i(Object obj) {
        this.a = obj;
    }

    public static synchronized i a() {
        try {
            if (b == null) {
                b = new i();
            }
        } catch (Throwable th) {
            throw th;
        }
        return b;
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void V(int i) {
        ((com.google.android.gms.common.api.f) this.a).V(i);
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void X() {
        ((com.google.android.gms.common.api.f) this.a).X();
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1654d
    public void b(ConnectionResult connectionResult) {
        boolean z = connectionResult.b == 0;
        AbstractC1655e abstractC1655e = (AbstractC1655e) this.a;
        if (z) {
            abstractC1655e.k(null, abstractC1655e.l());
            return;
        }
        InterfaceC1653c interfaceC1653c = abstractC1655e.p;
        if (interfaceC1653c != null) {
            interfaceC1653c.f0(connectionResult);
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) {
        ((com.google.android.gms.common.api.g) this.a).f0(connectionResult);
    }
}
