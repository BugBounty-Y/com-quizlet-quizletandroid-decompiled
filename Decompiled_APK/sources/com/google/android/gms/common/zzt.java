package com.google.android.gms.common;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3501n3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3507o3;

/* loaded from: classes2.dex */
public final class zzt extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzt> CREATOR = new i(3);
    public final boolean a;
    public final String b;
    public final int c;
    public final int d;
    public final long e;
    public final zzt f;

    public zzt(boolean z, String str, int i, int i2, long j, zzt zztVar) {
        this.a = z;
        this.b = str;
        this.c = AbstractC3501n3.c(i) - 1;
        this.d = AbstractC3507o3.d(i2) - 1;
        this.e = j;
        this.f = zztVar;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a ? 1 : 0);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.m(parcel, 5, 8);
        parcel.writeLong(this.e);
        AbstractC3489l3.g(parcel, 6, this.f, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
