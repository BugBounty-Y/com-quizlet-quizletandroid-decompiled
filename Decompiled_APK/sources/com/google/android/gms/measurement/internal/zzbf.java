package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_barcode.C3308z;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class zzbf extends AbstractSafeParcelable implements Iterable<String> {
    public static final Parcelable.Creator<zzbf> CREATOR = new com.google.android.gms.fido.fido2.api.common.i(11);
    public final Bundle a;

    public zzbf(Bundle bundle) {
        this.a = bundle;
    }

    public final Bundle a() {
        return new Bundle(this.a);
    }

    public final Double b() {
        return Double.valueOf(this.a.getDouble("value"));
    }

    public final Object c(String str) {
        return this.a.get(str);
    }

    public final String g() {
        return this.a.getString("currency");
    }

    @Override // java.lang.Iterable
    public final Iterator<String> iterator() {
        return new C3308z(this);
    }

    public final String toString() {
        return this.a.toString();
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.c(parcel, 2, a());
        AbstractC3489l3.o(iN, parcel);
    }
}
