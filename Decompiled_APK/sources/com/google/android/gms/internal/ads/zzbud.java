package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.view.View;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzbud extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbud> CREATOR = new C2128h6(9);
    public final View a;
    public final Map b;

    public zzbud(IBinder iBinder, IBinder iBinder2) {
        this.a = (View) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder));
        this.b = (Map) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder2));
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.e(parcel, 1, new com.google.android.gms.dynamic.b(this.a));
        AbstractC3489l3.e(parcel, 2, new com.google.android.gms.dynamic.b(this.b));
        AbstractC3489l3.o(iN, parcel);
    }
}
