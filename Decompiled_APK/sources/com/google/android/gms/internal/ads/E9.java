package com.google.android.gms.internal.ads;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1653c;

/* loaded from: classes2.dex */
public final class E9 implements InterfaceC1653c, InterfaceC2399nd {
    public final /* synthetic */ C2313ld a;

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b */
    public void mo21b(Object obj) {
        this.a.c((InterfaceC2051fa) obj);
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) {
        this.a.d(new RuntimeException("Connection failed."));
    }
}
