package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzfpd extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzfpd> CREATOR = new C2128h6(22);
    public final int a;
    public final String b;
    public final String c;

    public zzfpd(int i, String str, String str2) {
        this.a = i;
        this.b = str;
        this.c = str2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.o(iN, parcel);
    }
}
