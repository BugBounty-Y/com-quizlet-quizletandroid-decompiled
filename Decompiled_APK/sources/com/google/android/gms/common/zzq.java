package com.google.android.gms.common;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzq extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzq> CREATOR = new com.google.android.gms.ads.internal.f(29);
    public final int a;
    public final boolean b;

    public zzq(int i, boolean z) {
        this.a = i;
        this.b = z;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }
}
