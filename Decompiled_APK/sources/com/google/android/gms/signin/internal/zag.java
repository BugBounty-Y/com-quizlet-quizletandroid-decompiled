package com.google.android.gms.signin.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.k;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.fido.fido2.api.common.i;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zag extends AbstractSafeParcelable implements k {
    public static final Parcelable.Creator<zag> CREATOR = new i(20);
    public final ArrayList a;
    public final String b;

    public zag(ArrayList arrayList, String str) {
        this.a = arrayList;
        this.b = str;
    }

    @Override // com.google.android.gms.common.api.k
    public final Status getStatus() {
        return this.b != null ? Status.e : Status.i;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.j(parcel, 1, this.a);
        AbstractC3489l3.h(parcel, 2, this.b);
        AbstractC3489l3.o(iN, parcel);
    }
}
