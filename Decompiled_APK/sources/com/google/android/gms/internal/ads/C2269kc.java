package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.kc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2269kc extends AbstractC2771w5 implements InterfaceC2312lc {
    public C2269kc(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.rewarded.client.IRewardItem", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2312lc
    public final String f() {
        Parcel parcelY3 = Y3(1, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2312lc
    public final int zze() {
        Parcel parcelY3 = Y3(2, f3());
        int i = parcelY3.readInt();
        parcelY3.recycle();
        return i;
    }
}
