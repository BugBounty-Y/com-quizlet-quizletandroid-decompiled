package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzbfv extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbfv> CREATOR = new C2128h6(2);
    public final int a;
    public final boolean b;
    public final int c;
    public final boolean d;
    public final int e;
    public final zzfw f;
    public final boolean g;
    public final int h;
    public final int i;
    public final boolean j;
    public final int k;

    public zzbfv(int i, boolean z, int i2, boolean z2, int i3, zzfw zzfwVar, boolean z3, int i4, int i5, boolean z4, int i6) {
        this.a = i;
        this.b = z;
        this.c = i2;
        this.d = z2;
        this.e = i3;
        this.f = zzfwVar;
        this.g = z3;
        this.h = i4;
        this.j = z4;
        this.i = i5;
        this.k = i6;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b ? 1 : 0);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.g(parcel, 6, this.f, i);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.h);
        AbstractC3489l3.m(parcel, 9, 4);
        parcel.writeInt(this.i);
        AbstractC3489l3.m(parcel, 10, 4);
        parcel.writeInt(this.j ? 1 : 0);
        AbstractC3489l3.m(parcel, 11, 4);
        parcel.writeInt(this.k);
        AbstractC3489l3.o(iN, parcel);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public zzbfv(com.google.android.gms.ads.formats.b bVar) {
        com.google.android.gms.ads.t tVar = bVar.f;
        this(4, bVar.a, bVar.b, bVar.d, bVar.e, tVar != null ? new zzfw(tVar) : null, bVar.g, bVar.c, 0, false, 0);
    }
}
