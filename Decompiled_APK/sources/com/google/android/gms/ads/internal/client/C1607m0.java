package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* renamed from: com.google.android.gms.ads.internal.client.m0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1607m0 extends AbstractC2771w5 implements InterfaceC1609n0 {
    public C1607m0(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IOnPaidEventListener", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1609n0
    public final void R2(zzt zztVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zztVar);
        d4(1, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1609n0
    public final boolean f() {
        Parcel parcelY3 = Y3(2, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }
}
