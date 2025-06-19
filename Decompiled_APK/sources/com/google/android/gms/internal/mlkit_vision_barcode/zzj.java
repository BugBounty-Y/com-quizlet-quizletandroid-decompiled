package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzj extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzj> CREATOR = new C3091a(11);
    public int a;
    public int b;
    public int c;
    public int d;
    public int e;
    public int f;
    public boolean g;
    public String h;

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.h(parcel, 9, this.h);
        AbstractC3489l3.o(iN, parcel);
    }
}
