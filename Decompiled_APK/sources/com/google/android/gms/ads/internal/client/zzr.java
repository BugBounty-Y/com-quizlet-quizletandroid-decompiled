package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzr extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzr> CREATOR = new C1589d0(9);
    public final String a;
    public final int b;
    public final int c;
    public final boolean d;
    public final int e;
    public final int f;
    public final zzr[] g;
    public final boolean h;
    public final boolean i;
    public boolean j;
    public final boolean k;
    public final boolean l;
    public final boolean m;
    public final boolean n;
    public final boolean o;

    /* JADX WARN: Removed duplicated region for block: B:41:0x00d2  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00e7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public zzr(android.content.Context r17, com.google.android.gms.ads.h[] r18) {
        /*
            Method dump skipped, instructions count: 395
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.zzr.<init>(android.content.Context, com.google.android.gms.ads.h[]):void");
    }

    public static zzr a() {
        return new zzr("interstitial_mb", 0, 0, false, 0, 0, null, false, false, false, false, true, false, false, false);
    }

    public static zzr b() {
        return new zzr("320x50_mb", 0, 0, false, 0, 0, null, true, false, false, false, false, false, false, false);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.m(parcel, 7, 4);
        parcel.writeInt(this.f);
        AbstractC3489l3.k(parcel, 8, this.g, i);
        AbstractC3489l3.m(parcel, 9, 4);
        parcel.writeInt(this.h ? 1 : 0);
        AbstractC3489l3.m(parcel, 10, 4);
        parcel.writeInt(this.i ? 1 : 0);
        boolean z = this.j;
        AbstractC3489l3.m(parcel, 11, 4);
        parcel.writeInt(z ? 1 : 0);
        AbstractC3489l3.m(parcel, 12, 4);
        parcel.writeInt(this.k ? 1 : 0);
        AbstractC3489l3.m(parcel, 13, 4);
        parcel.writeInt(this.l ? 1 : 0);
        AbstractC3489l3.m(parcel, 14, 4);
        parcel.writeInt(this.m ? 1 : 0);
        AbstractC3489l3.m(parcel, 15, 4);
        parcel.writeInt(this.n ? 1 : 0);
        AbstractC3489l3.m(parcel, 16, 4);
        parcel.writeInt(this.o ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzr(String str, int i, int i2, boolean z, int i3, int i4, zzr[] zzrVarArr, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8, boolean z9) {
        this.a = str;
        this.b = i;
        this.c = i2;
        this.d = z;
        this.e = i3;
        this.f = i4;
        this.g = zzrVarArr;
        this.h = z2;
        this.i = z3;
        this.j = z4;
        this.k = z5;
        this.l = z6;
        this.m = z7;
        this.n = z8;
        this.o = z9;
    }

    public zzr() {
        this("interstitial_mb", 0, 0, true, 0, 0, null, false, false, false, false, false, false, false, false);
    }

    public zzr(Context context, com.google.android.gms.ads.h hVar) {
        this(context, new com.google.android.gms.ads.h[]{hVar});
    }
}
