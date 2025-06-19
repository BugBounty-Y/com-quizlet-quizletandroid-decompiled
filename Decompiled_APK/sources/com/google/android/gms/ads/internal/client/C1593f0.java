package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* renamed from: com.google.android.gms.ads.internal.client.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1593f0 extends AbstractC2771w5 implements InterfaceC1595g0 {
    @Override // com.google.android.gms.ads.internal.client.InterfaceC1595g0
    public final String f() {
        Parcel parcelY3 = Y3(2, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1595g0
    public final String zze() {
        Parcel parcelY3 = Y3(1, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }
}
