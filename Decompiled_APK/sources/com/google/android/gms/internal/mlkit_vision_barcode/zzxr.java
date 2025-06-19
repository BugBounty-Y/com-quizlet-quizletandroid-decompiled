package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzxr extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzxr> CREATOR = new C3091a(18);
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final zzxq f;
    public final zzxq g;

    public zzxr(String str, String str2, String str3, String str4, String str5, zzxq zzxqVar, zzxq zzxqVar2) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = str5;
        this.f = zzxqVar;
        this.g = zzxqVar2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.h(parcel, 4, this.d);
        AbstractC3489l3.h(parcel, 5, this.e);
        AbstractC3489l3.g(parcel, 6, this.f, i);
        AbstractC3489l3.g(parcel, 7, this.g, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
