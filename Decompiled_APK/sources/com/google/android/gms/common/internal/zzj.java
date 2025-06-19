package com.google.android.gms.common.internal;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zzj extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzj> CREATOR = new com.google.android.gms.ads.internal.f(22);
    public Bundle a;
    public Feature[] b;
    public int c;
    public ConnectionTelemetryConfiguration d;

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.c(parcel, 1, this.a);
        AbstractC3489l3.k(parcel, 2, this.b, i);
        AbstractC3489l3.m(parcel, 3, 4);
        parcel.writeInt(this.c);
        AbstractC3489l3.g(parcel, 4, this.d, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
