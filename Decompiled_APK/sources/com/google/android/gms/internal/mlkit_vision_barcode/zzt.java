package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzt extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzt> CREATOR = new C3091a(6);
    public String a;
    public String b;
    public int c;

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.o(iN, parcel);
    }
}
