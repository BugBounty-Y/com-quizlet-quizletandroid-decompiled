package com.google.android.gms.internal.ads;

import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.pc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2484pc extends AbstractC2771w5 implements InterfaceC2569rc {
    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void f() {
        d4(6, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void h() {
        d4(2, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void h3(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(5, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void i() {
        d4(1, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void k0(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(4, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void q0(InterfaceC2312lc interfaceC2312lc) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC2312lc);
        d4(3, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void zze() {
        d4(7, f3());
    }
}
