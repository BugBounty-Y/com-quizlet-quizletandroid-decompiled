package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzbut extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbut> CREATOR = new C2128h6(11);
    public final boolean a;
    public final List b;

    public zzbut(boolean z, List list) {
        this.a = z;
        this.b = list;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 2, 4);
        parcel.writeInt(this.a ? 1 : 0);
        AbstractC3489l3.j(parcel, 3, this.b);
        AbstractC3489l3.o(iN, parcel);
    }
}
