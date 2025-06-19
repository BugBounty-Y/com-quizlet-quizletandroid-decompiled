package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class Xi extends com.google.android.gms.ads.internal.client.u0 {
    public final Object a = new Object();
    public final com.google.android.gms.ads.internal.client.v0 b;
    public final InterfaceC1707Ia c;

    public Xi(com.google.android.gms.ads.internal.client.v0 v0Var, InterfaceC1707Ia interfaceC1707Ia) {
        this.b = v0Var;
        this.c = interfaceC1707Ia;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void E(boolean z) throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void e2(com.google.android.gms.ads.internal.client.w0 w0Var) {
        synchronized (this.a) {
            try {
                com.google.android.gms.ads.internal.client.v0 v0Var = this.b;
                if (v0Var != null) {
                    v0Var.e2(w0Var);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float f() {
        InterfaceC1707Ia interfaceC1707Ia = this.c;
        return interfaceC1707Ia != null ? interfaceC1707Ia.h() : DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final int g() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float h() {
        InterfaceC1707Ia interfaceC1707Ia = this.c;
        return interfaceC1707Ia != null ? interfaceC1707Ia.g() : DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void k() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void m() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final boolean o() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final boolean p() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void t() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final boolean x() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float zze() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final com.google.android.gms.ads.internal.client.w0 zzi() {
        synchronized (this.a) {
            try {
                com.google.android.gms.ads.internal.client.v0 v0Var = this.b;
                if (v0Var == null) {
                    return null;
                }
                return v0Var.zzi();
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
