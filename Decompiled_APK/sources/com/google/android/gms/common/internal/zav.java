package com.google.android.gms.common.internal;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zav extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zav> CREATOR = new com.google.android.gms.ads.internal.f(20);
    public final int a;
    public final IBinder b;
    public final ConnectionResult c;
    public final boolean d;
    public final boolean e;

    public zav(int i, IBinder iBinder, ConnectionResult connectionResult, boolean z, boolean z2) {
        this.a = i;
        this.b = iBinder;
        this.c = connectionResult;
        this.d = z;
        this.e = z2;
    }

    public final boolean equals(Object obj) {
        Object f;
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zav)) {
            return false;
        }
        zav zavVar = (zav) obj;
        if (!this.c.equals(zavVar.c)) {
            return false;
        }
        Object f2 = null;
        IBinder iBinder = this.b;
        if (iBinder == null) {
            f = null;
        } else {
            int i = AbstractBinderC1651a.b;
            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.common.internal.IAccountAccessor");
            f = iInterfaceQueryLocalInterface instanceof InterfaceC1657g ? (InterfaceC1657g) iInterfaceQueryLocalInterface : new F(iBinder, "com.google.android.gms.common.internal.IAccountAccessor", 3);
        }
        IBinder iBinder2 = zavVar.b;
        if (iBinder2 != null) {
            int i2 = AbstractBinderC1651a.b;
            IInterface iInterfaceQueryLocalInterface2 = iBinder2.queryLocalInterface("com.google.android.gms.common.internal.IAccountAccessor");
            f2 = iInterfaceQueryLocalInterface2 instanceof InterfaceC1657g ? (InterfaceC1657g) iInterfaceQueryLocalInterface2 : new F(iBinder2, "com.google.android.gms.common.internal.IAccountAccessor", 3);
        }
        return u.l(f, f2);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.e(parcel, 2, this.b);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }
}
