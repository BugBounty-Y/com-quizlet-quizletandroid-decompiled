package com.google.android.gms.ads.internal.client;

import android.location.Location;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzm extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzm> CREATOR = new C1589d0(8);
    public final int a;
    public final long b;
    public final Bundle c;
    public final int d;
    public final List e;
    public final boolean f;
    public final int g;
    public final boolean h;
    public final String i;
    public final zzft j;
    public final Location k;
    public final String l;
    public final Bundle m;
    public final Bundle n;
    public final List o;
    public final String p;
    public final String q;
    public final boolean r;
    public final zzc s;
    public final int t;
    public final String u;
    public final List v;
    public final int w;
    public final String x;
    public final int y;
    public final long z;

    public zzm(int i, long j, Bundle bundle, int i2, List list, boolean z, int i3, boolean z2, String str, zzft zzftVar, Location location, String str2, Bundle bundle2, Bundle bundle3, List list2, String str3, String str4, boolean z3, zzc zzcVar, int i4, String str5, List list3, int i5, String str6, int i6, long j2) {
        this.a = i;
        this.b = j;
        this.c = bundle == null ? new Bundle() : bundle;
        this.d = i2;
        this.e = list;
        this.f = z;
        this.g = i3;
        this.h = z2;
        this.i = str;
        this.j = zzftVar;
        this.k = location;
        this.l = str2;
        this.m = bundle2 == null ? new Bundle() : bundle2;
        this.n = bundle3;
        this.o = list2;
        this.p = str3;
        this.q = str4;
        this.r = z3;
        this.s = zzcVar;
        this.t = i4;
        this.u = str5;
        this.v = list3 == null ? new ArrayList() : list3;
        this.w = i5;
        this.x = str6;
        this.y = i6;
        this.z = j2;
    }

    public final boolean a(zzm zzmVar) {
        if (zzmVar == null) {
            return false;
        }
        return this.a == zzmVar.a && this.b == zzmVar.b && com.google.android.gms.ads.internal.util.client.i.a(this.c, zzmVar.c) && this.d == zzmVar.d && com.google.android.gms.common.internal.u.l(this.e, zzmVar.e) && this.f == zzmVar.f && this.g == zzmVar.g && this.h == zzmVar.h && com.google.android.gms.common.internal.u.l(this.i, zzmVar.i) && com.google.android.gms.common.internal.u.l(this.j, zzmVar.j) && com.google.android.gms.common.internal.u.l(this.k, zzmVar.k) && com.google.android.gms.common.internal.u.l(this.l, zzmVar.l) && com.google.android.gms.ads.internal.util.client.i.a(this.m, zzmVar.m) && com.google.android.gms.ads.internal.util.client.i.a(this.n, zzmVar.n) && com.google.android.gms.common.internal.u.l(this.o, zzmVar.o) && com.google.android.gms.common.internal.u.l(this.p, zzmVar.p) && com.google.android.gms.common.internal.u.l(this.q, zzmVar.q) && this.r == zzmVar.r && this.t == zzmVar.t && com.google.android.gms.common.internal.u.l(this.u, zzmVar.u) && com.google.android.gms.common.internal.u.l(this.v, zzmVar.v) && this.w == zzmVar.w && com.google.android.gms.common.internal.u.l(this.x, zzmVar.x) && this.y == zzmVar.y;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof zzm) {
            return a((zzm) obj) && this.z == ((zzm) obj).z;
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(this.a), Long.valueOf(this.b), this.c, Integer.valueOf(this.d), this.e, Boolean.valueOf(this.f), Integer.valueOf(this.g), Boolean.valueOf(this.h), this.i, this.j, this.k, this.l, this.m, this.n, this.o, this.p, this.q, Boolean.valueOf(this.r), Integer.valueOf(this.t), this.u, this.v, Integer.valueOf(this.w), this.x, Integer.valueOf(this.y), Long.valueOf(this.z)});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 8);
        parcel.writeLong(this.b);
        AbstractC3489l3.c(parcel, 3, this.c);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d);
        AbstractC3489l3.j(parcel, 5, this.e);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.f ? 1 : 0);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.g);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.h ? 1 : 0);
        AbstractC3489l3.h(parcel, 9, this.i);
        AbstractC3489l3.g(parcel, 10, this.j, i);
        AbstractC3489l3.g(parcel, 11, this.k, i);
        AbstractC3489l3.h(parcel, 12, this.l);
        AbstractC3489l3.c(parcel, 13, this.m);
        AbstractC3489l3.c(parcel, 14, this.n);
        AbstractC3489l3.j(parcel, 15, this.o);
        AbstractC3489l3.h(parcel, 16, this.p);
        AbstractC3489l3.h(parcel, 17, this.q);
        AbstractC3489l3.m(parcel, 18, 4);
        parcel.writeInt(this.r ? 1 : 0);
        AbstractC3489l3.g(parcel, 19, this.s, i);
        AbstractC3489l3.m(parcel, 20, 4);
        parcel.writeInt(this.t);
        AbstractC3489l3.h(parcel, 21, this.u);
        AbstractC3489l3.j(parcel, 22, this.v);
        AbstractC3489l3.m(parcel, 23, 4);
        parcel.writeInt(this.w);
        AbstractC3489l3.h(parcel, 24, this.x);
        AbstractC3489l3.m(parcel, 25, 4);
        parcel.writeInt(this.y);
        AbstractC3489l3.m(parcel, 26, 8);
        parcel.writeLong(this.z);
        AbstractC3489l3.o(iN, parcel);
    }
}
