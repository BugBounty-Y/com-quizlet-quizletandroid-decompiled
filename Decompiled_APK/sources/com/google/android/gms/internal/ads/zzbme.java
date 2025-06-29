package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzbme extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbme> CREATOR = new C2128h6(6);
    public final String a;
    public final Bundle b;

    public zzbme(Bundle bundle, String str) {
        this.a = str;
        this.b = bundle;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 1, this.a);
        AbstractC3489l3.c(parcel, 2, this.b);
        AbstractC3489l3.o(iN, parcel);
    }
}
