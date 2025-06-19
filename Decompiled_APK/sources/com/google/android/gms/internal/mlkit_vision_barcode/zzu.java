package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.Point;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzu extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzu> CREATOR = new C3091a(10);
    public int a;
    public String b;
    public String c;
    public int d;
    public Point[] e;
    public zzn f;
    public zzq g;
    public zzr h;
    public zzt i;
    public zzs j;
    public zzo k;
    public zzk l;
    public zzl m;
    public zzm n;
    public byte[] o;
    public boolean p;
    public double q;

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.k(parcel, 6, this.e, i);
        AbstractC3489l3.g(parcel, 7, this.f, i);
        AbstractC3489l3.g(parcel, 8, this.g, i);
        AbstractC3489l3.g(parcel, 9, this.h, i);
        AbstractC3489l3.g(parcel, 10, this.i, i);
        AbstractC3489l3.g(parcel, 11, this.j, i);
        AbstractC3489l3.g(parcel, 12, this.k, i);
        AbstractC3489l3.g(parcel, 13, this.l, i);
        AbstractC3489l3.g(parcel, 14, this.m, i);
        AbstractC3489l3.g(parcel, 15, this.n, i);
        AbstractC3489l3.d(parcel, 16, this.o);
        AbstractC3489l3.m(parcel, 17, 4);
        parcel.writeInt(this.p ? 1 : 0);
        AbstractC3489l3.m(parcel, 18, 8);
        parcel.writeDouble(this.q);
        AbstractC3489l3.o(iN, parcel);
    }
}
