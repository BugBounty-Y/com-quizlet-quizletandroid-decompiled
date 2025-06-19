package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzfpa extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzfpa> CREATOR = new C2128h6(21);
    public final int a;
    public final byte[] b;

    public zzfpa(int i, byte[] bArr) {
        this.a = i;
        this.b = bArr;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.d(parcel, 2, this.b);
        AbstractC3489l3.o(iN, parcel);
    }
}
