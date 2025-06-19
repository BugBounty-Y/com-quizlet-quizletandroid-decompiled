package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzblj extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzblj> CREATOR = new C2128h6(4);
    public final boolean a;
    public final String b;
    public final int c;
    public final byte[] d;
    public final String[] e;
    public final String[] f;
    public final boolean g;
    public final long h;

    public zzblj(boolean z, String str, int i, byte[] bArr, String[] strArr, String[] strArr2, boolean z2, long j) {
        this.a = z;
        this.b = str;
        this.c = i;
        this.d = bArr;
        this.e = strArr;
        this.f = strArr2;
        this.g = z2;
        this.h = j;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a ? 1 : 0);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.d(parcel, 4, this.d);
        AbstractC3489l3.i(parcel, 5, this.e);
        AbstractC3489l3.i(parcel, 6, this.f);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.m(parcel, 8, 8);
        parcel.writeLong(this.h);
        AbstractC3489l3.o(iN, parcel);
    }
}
