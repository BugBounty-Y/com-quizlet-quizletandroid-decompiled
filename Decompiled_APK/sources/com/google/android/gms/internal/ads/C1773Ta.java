package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.Ta, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1773Ta extends AbstractC2771w5 implements InterfaceC1779Ua {
    public C1773Ta(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.mediation.client.rtb.IBannerCallback", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1779Ua
    public final void r(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(3, parcelF3);
    }
}
