package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzxt extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzxt> CREATOR = new C3091a(20);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;
    public final String l;
    public final String m;
    public final String n;

    public zzxt(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = str5;
        this.f = str6;
        this.g = str7;
        this.h = str8;
        this.i = str9;
        this.j = str10;
        this.k = str11;
        this.l = str12;
        this.m = str13;
        this.n = str14;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.h(parcel, 5, this.e);
        AbstractC3489l3.h(parcel, 6, this.f);
        AbstractC3489l3.h(parcel, 7, this.g);
        AbstractC3489l3.h(parcel, 8, this.h);
        AbstractC3489l3.h(parcel, 9, this.i);
        AbstractC3489l3.h(parcel, 10, this.j);
        AbstractC3489l3.h(parcel, 11, this.k);
        AbstractC3489l3.h(parcel, 12, this.l);
        AbstractC3489l3.h(parcel, 13, this.m);
        AbstractC3489l3.h(parcel, 14, this.n);
        AbstractC3489l3.o(iN, parcel);
    }
}
