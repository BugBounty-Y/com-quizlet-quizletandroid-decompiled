package com.google.android.gms.ads.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzl extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzl> CREATOR = new f(0);
    public final boolean a;
    public final boolean b;
    public final String c;
    public final boolean d;
    public final float e;
    public final int f;
    public final boolean g;
    public final boolean h;
    public final boolean i;

    public zzl(boolean z, boolean z2, String str, boolean z3, float f, int i, boolean z4, boolean z5, boolean z6) {
        this.a = z;
        this.b = z2;
        this.c = str;
        this.d = z3;
        this.e = f;
        this.f = i;
        this.g = z4;
        this.h = z5;
        this.i = z6;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.a ? 1 : 0);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeFloat(this.e);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.m(parcel, 9, 4);
        parcel.writeInt(this.h ? 1 : 0);
        AbstractC3489l3.m(parcel, 10, 4);
        parcel.writeInt(this.i ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzl(boolean z, boolean z2, boolean z3, float f, boolean z4, boolean z5, boolean z6) {
        this(z, z2, null, z3, f, -1, z4, z5, z6);
    }
}
