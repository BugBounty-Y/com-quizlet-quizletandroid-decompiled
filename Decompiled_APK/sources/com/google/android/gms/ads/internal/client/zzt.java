package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzt extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzt> CREATOR = new C1589d0(10);
    public final int a;
    public final int b;
    public final String c;
    public final long d;

    public zzt(long j, int i, int i2, String str) {
        this.a = i;
        this.b = i2;
        this.c = str;
        this.d = j;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.m(parcel, 4, 8);
        parcel.writeLong(this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
