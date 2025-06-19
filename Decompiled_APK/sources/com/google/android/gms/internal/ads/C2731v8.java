package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.v8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2731v8 extends AbstractC2771w5 implements InterfaceC2774w8 {
    public C2731v8(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.formats.client.IMediaContent", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final com.google.android.gms.ads.internal.client.v0 g() {
        Parcel parcelY3 = Y3(7, f3());
        com.google.android.gms.ads.internal.client.v0 v0VarE4 = com.google.android.gms.ads.internal.client.u0.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return v0VarE4;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final boolean k() {
        Parcel parcelY3 = Y3(8, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final boolean t() {
        Parcel parcelY3 = Y3(10, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final com.google.android.gms.dynamic.a zzi() {
        return assistantMode.refactored.a.h(Y3(4, f3()));
    }
}
