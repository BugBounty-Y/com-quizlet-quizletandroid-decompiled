package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.Ya, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1803Ya extends AbstractC2771w5 implements InterfaceC1809Za {
    public C1803Ya(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.mediation.client.rtb.INativeCallback", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1809Za
    public final void r(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(3, parcelF3);
    }
}
