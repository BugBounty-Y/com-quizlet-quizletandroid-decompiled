package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzan extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzan> CREATOR = new C3091a(8);
    public int a;
    public final int b;
    public final int c;
    public final long d;
    public final int e;

    public zzan(int i, long j, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = j;
        this.e = i4;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        int i2 = this.a;
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(i2);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 5, 8);
        parcel.writeLong(this.d);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.o(iN, parcel);
    }
}
