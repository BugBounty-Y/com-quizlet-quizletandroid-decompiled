package com.google.android.gms.internal.measurement;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzdh extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzdh> CREATOR = new T(0);
    public final long a;
    public final long b;
    public final boolean c;
    public final String d;
    public final String e;
    public final String f;
    public final Bundle g;
    public final String h;

    public zzdh(long j, long j2, boolean z, String str, String str2, String str3, Bundle bundle, String str4) {
        this.a = j;
        this.b = j2;
        this.c = z;
        this.d = str;
        this.e = str2;
        this.f = str3;
        this.g = bundle;
        this.h = str4;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 8);
        parcel.writeLong(this.a);
        AbstractC3489l3.m(parcel, 2, 8);
        parcel.writeLong(this.b);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c ? 1 : 0);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.h(parcel, 5, this.e);
        AbstractC3489l3.h(parcel, 6, this.f);
        AbstractC3489l3.c(parcel, 7, this.g);
        AbstractC3489l3.h(parcel, 8, this.h);
        AbstractC3489l3.o(iN, parcel);
    }
}
