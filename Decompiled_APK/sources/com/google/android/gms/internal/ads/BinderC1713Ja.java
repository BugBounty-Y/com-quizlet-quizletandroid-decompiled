package com.google.android.gms.internal.ads;

import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.Ja, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1713Ja extends com.google.android.gms.ads.internal.client.u0 {
    public final Object a = new Object();
    public volatile com.google.android.gms.ads.internal.client.w0 b;

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void E(boolean z) throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void e2(com.google.android.gms.ads.internal.client.w0 w0Var) {
        synchronized (this.a) {
            this.b = w0Var;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float f() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final int g() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float h() throws RemoteException {
        throw new RemoteException();
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
        com.google.android.gms.ads.internal.client.w0 w0Var;
        synchronized (this.a) {
            w0Var = this.b;
        }
        return w0Var;
    }
}
