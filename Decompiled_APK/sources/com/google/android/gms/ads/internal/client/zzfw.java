package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzfw extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzfw> CREATOR = new C1589d0(7);
    public final boolean a;
    public final boolean b;
    public final boolean c;

    public zzfw(com.google.android.gms.ads.t tVar) {
        this(tVar.a, tVar.b, tVar.c);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.a ? 1 : 0);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzfw(boolean z, boolean z2, boolean z3) {
        this.a = z;
        this.b = z2;
        this.c = z3;
    }
}
