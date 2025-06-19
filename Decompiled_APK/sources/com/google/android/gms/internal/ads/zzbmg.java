package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzbmg extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbmg> CREATOR = new C2128h6(7);
    public final int a;
    public final int b;
    public final String c;
    public final int d;

    public zzbmg(int i, int i2, String str, int i3) {
        this.a = i;
        this.b = i2;
        this.c = str;
        this.d = i3;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.h(parcel, 2, this.c);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.m(parcel, 1000, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.o(iN, parcel);
    }
}
