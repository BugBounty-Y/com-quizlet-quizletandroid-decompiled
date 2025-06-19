package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzxs extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzxs> CREATOR = new C3091a(19);
    public final zzxw a;
    public final String b;
    public final String c;
    public final zzxx[] d;
    public final zzxu[] e;
    public final String[] f;
    public final zzxp[] g;

    public zzxs(zzxw zzxwVar, String str, String str2, zzxx[] zzxxVarArr, zzxu[] zzxuVarArr, String[] strArr, zzxp[] zzxpVarArr) {
        this.a = zzxwVar;
        this.b = str;
        this.c = str2;
        this.d = zzxxVarArr;
        this.e = zzxuVarArr;
        this.f = strArr;
        this.g = zzxpVarArr;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 1, this.a, i);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.k(parcel, 4, this.d, i);
        AbstractC3489l3.k(parcel, 5, this.e, i);
        AbstractC3489l3.i(parcel, 6, this.f);
        AbstractC3489l3.k(parcel, 7, this.g, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
