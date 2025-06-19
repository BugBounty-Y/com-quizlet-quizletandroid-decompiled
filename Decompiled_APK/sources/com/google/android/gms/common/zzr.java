package com.google.android.gms.common;

import android.content.Context;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzr extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzr> CREATOR = new i(2);
    public final String a;
    public final boolean b;
    public final boolean c;
    public final Context d;
    public final boolean e;
    public final boolean f;
    public final zzq g;

    public zzr(String str, boolean z, boolean z2, IBinder iBinder, boolean z3, boolean z4, zzq zzqVar) {
        this.a = str;
        this.b = z;
        this.c = z2;
        this.d = (Context) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder));
        this.e = z3;
        this.f = z4;
        this.g = zzqVar;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c ? 1 : 0);
        AbstractC3489l3.e(parcel, 4, new com.google.android.gms.dynamic.b(this.d));
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e ? 1 : 0);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.f ? 1 : 0);
        AbstractC3489l3.g(parcel, 7, this.g, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
