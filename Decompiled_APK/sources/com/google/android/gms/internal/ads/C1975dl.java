package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.ads.dl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1975dl implements InterfaceC1928ci {
    public final Bundle a = new Bundle();

    @Override // com.google.android.gms.internal.ads.InterfaceC1928ci
    public final synchronized void A(String str) {
        this.a.putInt(str, 1);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1928ci
    public final synchronized void I(String str) {
        this.a.putInt(str, 2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1928ci
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1928ci
    public final void zza(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1928ci
    public final synchronized void zzb(String str, String str2) {
        this.a.putInt(str, 3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1928ci
    public final void zze() {
    }
}
