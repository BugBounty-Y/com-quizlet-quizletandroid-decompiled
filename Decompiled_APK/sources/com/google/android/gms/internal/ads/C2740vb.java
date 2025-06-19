package com.google.android.gms.internal.ads;

import android.content.Intent;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.offline.buffering.zza;

/* renamed from: com.google.android.gms.internal.ads.vb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2740vb extends AbstractC2771w5 implements InterfaceC2783wb {
    public C2740vb(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.offline.IOfflineUtils", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void J3(com.google.android.gms.dynamic.a aVar, zza zzaVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzaVar);
        d4(6, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void Q1(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(4, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void g() {
        d4(3, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void l0(Intent intent) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, intent);
        d4(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2783wb
    public final void r1(String[] strArr, int[] iArr, com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        parcelF3.writeStringArray(strArr);
        parcelF3.writeIntArray(iArr);
        AbstractC2857y5.e(parcelF3, aVar);
        d4(5, parcelF3);
    }
}
