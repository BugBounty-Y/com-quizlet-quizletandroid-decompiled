package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.x8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2817x8 extends AbstractC2771w5 implements InterfaceC2860y8 {
    public C2817x8(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.formats.client.INativeAdImage", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final int a() {
        Parcel parcelY3 = Y3(5, f3());
        int i = parcelY3.readInt();
        parcelY3.recycle();
        return i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final com.google.android.gms.dynamic.a f() {
        return assistantMode.refactored.a.h(Y3(1, f3()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final int j() {
        Parcel parcelY3 = Y3(4, f3());
        int i = parcelY3.readInt();
        parcelY3.recycle();
        return i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final double zzb() {
        Parcel parcelY3 = Y3(3, f3());
        double d = parcelY3.readDouble();
        parcelY3.recycle();
        return d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2860y8
    public final Uri zze() {
        Parcel parcelY3 = Y3(2, f3());
        Uri uri = (Uri) AbstractC2857y5.a(parcelY3, Uri.CREATOR);
        parcelY3.recycle();
        return uri;
    }
}
