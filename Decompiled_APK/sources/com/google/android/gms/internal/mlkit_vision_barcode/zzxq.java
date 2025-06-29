package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzxq extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzxq> CREATOR = new C3091a(17);
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final boolean g;
    public final String h;

    public zzxq(int i, int i2, int i3, int i4, int i5, int i6, boolean z, String str) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = i5;
        this.f = i6;
        this.g = z;
        this.h = str;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.h(parcel, 8, this.h);
        AbstractC3489l3.o(iN, parcel);
    }
}
