package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzk extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzk> CREATOR = new C3091a(12);
    public String a;
    public String b;
    public String c;
    public String d;
    public String e;
    public zzj f;
    public zzj g;

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.h(parcel, 5, this.d);
        AbstractC3489l3.h(parcel, 6, this.e);
        AbstractC3489l3.g(parcel, 7, this.f, i);
        AbstractC3489l3.g(parcel, 8, this.g, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
