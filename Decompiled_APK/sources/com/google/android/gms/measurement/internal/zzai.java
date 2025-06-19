package com.google.android.gms.measurement.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzai extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzai> CREATOR = new com.google.android.gms.fido.fido2.api.common.i(9);
    public String a;
    public String b;
    public zzqb c;
    public long d;
    public boolean e;
    public String f;
    public final zzbh g;
    public long h;
    public zzbh i;
    public final long j;
    public final zzbh k;

    public zzai(zzai zzaiVar) {
        com.google.android.gms.common.internal.u.h(zzaiVar);
        this.a = zzaiVar.a;
        this.b = zzaiVar.b;
        this.c = zzaiVar.c;
        this.d = zzaiVar.d;
        this.e = zzaiVar.e;
        this.f = zzaiVar.f;
        this.g = zzaiVar.g;
        this.h = zzaiVar.h;
        this.i = zzaiVar.i;
        this.j = zzaiVar.j;
        this.k = zzaiVar.k;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.g(parcel, 4, this.c, i);
        long j = this.d;
        AbstractC3489l3.m(parcel, 5, 8);
        parcel.writeLong(j);
        boolean z = this.e;
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(z ? 1 : 0);
        AbstractC3489l3.h(parcel, 7, this.f);
        AbstractC3489l3.g(parcel, 8, this.g, i);
        long j2 = this.h;
        AbstractC3489l3.m(parcel, 9, 8);
        parcel.writeLong(j2);
        AbstractC3489l3.g(parcel, 10, this.i, i);
        AbstractC3489l3.m(parcel, 11, 8);
        parcel.writeLong(this.j);
        AbstractC3489l3.g(parcel, 12, this.k, i);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzai(String str, String str2, zzqb zzqbVar, long j, boolean z, String str3, zzbh zzbhVar, long j2, zzbh zzbhVar2, long j3, zzbh zzbhVar3) {
        this.a = str;
        this.b = str2;
        this.c = zzqbVar;
        this.d = j;
        this.e = z;
        this.f = str3;
        this.g = zzbhVar;
        this.h = j2;
        this.i = zzbhVar2;
        this.j = j3;
        this.k = zzbhVar3;
    }
}
