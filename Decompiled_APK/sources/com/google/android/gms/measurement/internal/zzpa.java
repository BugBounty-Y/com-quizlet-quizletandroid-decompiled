package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzpa extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzpa> CREATOR = new com.google.android.gms.fido.fido2.api.common.i(14);
    public final long a;
    public byte[] b;
    public final String c;
    public final Bundle d;
    public final int e;
    public final long f;
    public String g;

    public zzpa(long j, byte[] bArr, String str, Bundle bundle, int i, long j2, String str2) {
        this.a = j;
        this.b = bArr;
        this.c = str;
        this.d = bundle;
        this.e = i;
        this.f = j2;
        this.g = str2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 8);
        parcel.writeLong(this.a);
        AbstractC3489l3.d(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.c(parcel, 4, this.d);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.m(parcel, 6, 8);
        parcel.writeLong(this.f);
        AbstractC3489l3.h(parcel, 7, this.g);
        AbstractC3489l3.o(iN, parcel);
    }
}
