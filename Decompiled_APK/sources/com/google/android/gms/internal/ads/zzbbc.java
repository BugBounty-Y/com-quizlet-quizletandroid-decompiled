package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzbbc extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbbc> CREATOR = new C2128h6(0);
    public ParcelFileDescriptor a;
    public final boolean b;
    public final boolean c;
    public final long d;
    public final boolean e;

    public zzbbc(ParcelFileDescriptor parcelFileDescriptor, boolean z, boolean z2, long j, boolean z3) {
        this.a = parcelFileDescriptor;
        this.b = z;
        this.c = z2;
        this.d = j;
        this.e = z3;
    }

    public final synchronized ParcelFileDescriptor.AutoCloseInputStream a() {
        if (this.a == null) {
            return null;
        }
        ParcelFileDescriptor.AutoCloseInputStream autoCloseInputStream = new ParcelFileDescriptor.AutoCloseInputStream(this.a);
        this.a = null;
        return autoCloseInputStream;
    }

    public final synchronized boolean b() {
        return this.a != null;
    }

    public final synchronized boolean c() {
        return this.c;
    }

    public final synchronized boolean g() {
        return this.e;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        ParcelFileDescriptor parcelFileDescriptor;
        boolean z;
        long j;
        int iN = AbstractC3489l3.n(20293, parcel);
        synchronized (this) {
            parcelFileDescriptor = this.a;
        }
        AbstractC3489l3.g(parcel, 2, parcelFileDescriptor, i);
        synchronized (this) {
            z = this.b;
        }
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(z ? 1 : 0);
        boolean zC = c();
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(zC ? 1 : 0);
        synchronized (this) {
            j = this.d;
        }
        AbstractC3489l3.m(parcel, 5, 8);
        parcel.writeLong(j);
        boolean zG = g();
        AbstractC3489l3.m(parcel, 6, 4);
        parcel.writeInt(zG ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }

    public zzbbc() {
        this(null, false, false, 0L, false);
    }
}
