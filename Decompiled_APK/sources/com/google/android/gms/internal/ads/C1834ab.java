package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.ab, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1834ab extends AbstractC2771w5 implements InterfaceC1878bb {
    public C1834ab(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.mediation.client.rtb.IRewardedCallback", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1878bb
    public final void r(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(4, parcelF3);
    }
}
