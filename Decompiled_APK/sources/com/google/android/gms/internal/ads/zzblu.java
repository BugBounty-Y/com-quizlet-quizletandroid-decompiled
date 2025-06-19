package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzblu extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzblu> CREATOR = new C2128h6(5);
    public final String a;
    public final boolean b;
    public final int c;
    public final String d;

    public zzblu(String str, int i, String str2, boolean z) {
        this.a = str;
        this.b = z;
        this.c = i;
        this.d = str2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.o(iN, parcel);
    }
}
