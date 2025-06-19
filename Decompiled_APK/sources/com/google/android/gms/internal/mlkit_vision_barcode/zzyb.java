package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.Point;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzyb extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzyb> CREATOR = new C3091a(15);
    public final int a;
    public final String b;
    public final String c;
    public final byte[] d;
    public final Point[] e;
    public final int f;
    public final zzxu g;
    public final zzxx h;
    public final zzxy i;
    public final zzya j;
    public final zzxz k;
    public final zzxv l;
    public final zzxr m;
    public final zzxs n;
    public final zzxt o;

    public zzyb(int i, String str, String str2, byte[] bArr, Point[] pointArr, int i2, zzxu zzxuVar, zzxx zzxxVar, zzxy zzxyVar, zzya zzyaVar, zzxz zzxzVar, zzxv zzxvVar, zzxr zzxrVar, zzxs zzxsVar, zzxt zzxtVar) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = bArr;
        this.e = pointArr;
        this.f = i2;
        this.g = zzxuVar;
        this.h = zzxxVar;
        this.i = zzxyVar;
        this.j = zzyaVar;
        this.k = zzxzVar;
        this.l = zzxvVar;
        this.m = zzxrVar;
        this.n = zzxsVar;
        this.o = zzxtVar;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.d(parcel, 4, this.d);
        AbstractC3489l3.k(parcel, 5, this.e, i);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.g(parcel, 7, this.g, i);
        AbstractC3489l3.g(parcel, 8, this.h, i);
        AbstractC3489l3.g(parcel, 9, this.i, i);
        AbstractC3489l3.g(parcel, 10, this.j, i);
        AbstractC3489l3.g(parcel, 11, this.k, i);
        AbstractC3489l3.g(parcel, 12, this.l, i);
        AbstractC3489l3.g(parcel, 13, this.m, i);
        AbstractC3489l3.g(parcel, 14, this.n, i);
        AbstractC3489l3.g(parcel, 15, this.o, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
