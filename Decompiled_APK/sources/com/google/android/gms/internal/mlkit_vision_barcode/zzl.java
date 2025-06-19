package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzl extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzl> CREATOR = new C3091a(14);
    public zzp a;
    public String b;
    public String c;
    public zzq[] d;
    public zzn[] e;
    public String[] f;
    public zzi[] g;

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 2, this.a, i);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.k(parcel, 5, this.d, i);
        AbstractC3489l3.k(parcel, 6, this.e, i);
        AbstractC3489l3.i(parcel, 7, this.f);
        AbstractC3489l3.k(parcel, 8, this.g, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
