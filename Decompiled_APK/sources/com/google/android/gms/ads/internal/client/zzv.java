package com.google.android.gms.ads.internal.client;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzv extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzv> CREATOR = new C1589d0(11);
    public final String a;
    public long b;
    public zze c;
    public final Bundle d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;

    public zzv(String str, long j, zze zzeVar, Bundle bundle, String str2, String str3, String str4, String str5) {
        this.a = str;
        this.b = j;
        this.c = zzeVar;
        this.d = bundle;
        this.e = str2;
        this.f = str3;
        this.g = str4;
        this.h = str5;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        long j = this.b;
        AbstractC3489l3.m(parcel, 2, 8);
        parcel.writeLong(j);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.c(parcel, 4, this.d);
        AbstractC3489l3.h(parcel, 5, this.e);
        AbstractC3489l3.h(parcel, 6, this.f);
        AbstractC3489l3.h(parcel, 7, this.g);
        AbstractC3489l3.h(parcel, 8, this.h);
        AbstractC3489l3.o(iN, parcel);
    }
}
