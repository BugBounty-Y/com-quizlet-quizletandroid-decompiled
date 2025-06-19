package com.google.android.gms.ads.internal.client;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.ads.internal.client.r0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1616r0 extends AbstractC2771w5 implements s0 {
    public C1616r0(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IResponseInfo", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final zzv f() {
        Parcel parcelY3 = Y3(4, f3());
        zzv zzvVar = (zzv) AbstractC2857y5.a(parcelY3, zzv.CREATOR);
        parcelY3.recycle();
        return zzvVar;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final String g() {
        Parcel parcelY3 = Y3(6, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final String h() {
        Parcel parcelY3 = Y3(1, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final List i() {
        Parcel parcelY3 = Y3(3, f3());
        ArrayList arrayListCreateTypedArrayList = parcelY3.createTypedArrayList(zzv.CREATOR);
        parcelY3.recycle();
        return arrayListCreateTypedArrayList;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final Bundle zze() {
        Parcel parcelY3 = Y3(5, f3());
        Bundle bundle = (Bundle) AbstractC2857y5.a(parcelY3, Bundle.CREATOR);
        parcelY3.recycle();
        return bundle;
    }

    @Override // com.google.android.gms.ads.internal.client.s0
    public final String zzi() {
        Parcel parcelY3 = Y3(2, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }
}
