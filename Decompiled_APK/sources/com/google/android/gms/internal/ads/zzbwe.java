package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzbwe extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbwe> CREATOR = new C2128h6(15);
    public final zzm a;
    public final String b;

    public zzbwe(zzm zzmVar, String str) {
        this.a = zzmVar;
        this.b = str;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 2, this.a, i);
        AbstractC3489l3.h(parcel, 3, this.b);
        AbstractC3489l3.o(iN, parcel);
    }
}
