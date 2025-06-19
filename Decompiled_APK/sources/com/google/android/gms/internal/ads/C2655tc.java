package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.tc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2655tc extends AbstractC2771w5 implements InterfaceC2741vc {
    public C2655tc(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.rewarded.client.IRewardedAdLoadCallback", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void h() {
        d4(1, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void r(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(3, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void u(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(2, parcelF3);
    }
}
