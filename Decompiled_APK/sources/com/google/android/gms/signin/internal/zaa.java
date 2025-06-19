package com.google.android.gms.signin.internal;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.k;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.fido.fido2.api.common.i;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

/* loaded from: classes2.dex */
public final class zaa extends AbstractSafeParcelable implements k {
    public static final Parcelable.Creator<zaa> CREATOR = new i(19);
    public final int a;
    public final int b;
    public final Intent c;

    public zaa(int i, int i2, Intent intent) {
        this.a = i;
        this.b = i2;
        this.c = intent;
    }

    @Override // com.google.android.gms.common.api.k
    public final Status getStatus() {
        return this.b == 0 ? Status.e : Status.i;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.b);
        AbstractC3489l3.g(parcel, 3, this.c, i);
        AbstractC3489l3.o(iN, parcel);
    }
}
