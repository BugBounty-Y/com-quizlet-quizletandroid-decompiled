package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzbyz extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbyz> CREATOR = new C2128h6(19);
    public final String a;
    public final String b;
    public final com.google.android.gms.ads.internal.client.zzr c;
    public final zzm d;
    public final int e;
    public final String f;

    public zzbyz(String str, String str2, com.google.android.gms.ads.internal.client.zzr zzrVar, zzm zzmVar, int i, String str3) {
        this.a = str;
        this.b = str2;
        this.c = zzrVar;
        this.d = zzmVar;
        this.e = i;
        this.f = str3;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.g(parcel, 4, this.d, i);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.h(parcel, 6, this.f);
        AbstractC3489l3.o(iN, parcel);
    }
}
