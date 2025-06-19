package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zze extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zze> CREATOR = new C1589d0(3);
    public final int a;
    public final String b;
    public final String c;
    public zze d;
    public IBinder e;

    public zze(int i, String str, String str2, zze zzeVar, IBinder iBinder) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = zzeVar;
        this.e = iBinder;
    }

    public final com.google.android.gms.ads.b a() {
        zze zzeVar = this.d;
        return new com.google.android.gms.ads.b(this.a, this.b, this.c, zzeVar != null ? new com.google.android.gms.ads.b(zzeVar.a, zzeVar.b, zzeVar.c, null) : null);
    }

    public final com.google.android.gms.ads.l b() {
        s0 c1616r0;
        zze zzeVar = this.d;
        com.google.android.gms.ads.b bVar = zzeVar == null ? null : new com.google.android.gms.ads.b(zzeVar.a, zzeVar.b, zzeVar.c, null);
        IBinder iBinder = this.e;
        if (iBinder == null) {
            c1616r0 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IResponseInfo");
            c1616r0 = iInterfaceQueryLocalInterface instanceof s0 ? (s0) iInterfaceQueryLocalInterface : new C1616r0(iBinder);
        }
        return new com.google.android.gms.ads.l(this.a, this.b, this.c, bVar, c1616r0 != null ? new com.google.android.gms.ads.q(c1616r0) : null);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.g(parcel, 4, this.d, i);
        AbstractC3489l3.e(parcel, 5, this.e);
        AbstractC3489l3.o(iN, parcel);
    }
}
