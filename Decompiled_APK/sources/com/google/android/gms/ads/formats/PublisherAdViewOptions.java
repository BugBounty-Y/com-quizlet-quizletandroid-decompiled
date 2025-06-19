package com.google.android.gms.ads.formats;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.internal.client.O;
import com.google.android.gms.ads.internal.client.P;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.ads.I5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;

@Deprecated
/* loaded from: classes2.dex */
public final class PublisherAdViewOptions extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<PublisherAdViewOptions> CREATOR = new android.support.v4.media.a(24);
    public final boolean a;
    public final P b;
    public final IBinder c;

    public PublisherAdViewOptions(boolean z, IBinder iBinder, IBinder iBinder2) {
        P o;
        this.a = z;
        if (iBinder != null) {
            int i = I5.b;
            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAppEventListener");
            o = iInterfaceQueryLocalInterface instanceof P ? (P) iInterfaceQueryLocalInterface : new O(iBinder);
        } else {
            o = null;
        }
        this.b = o;
        this.c = iBinder2;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.m(parcel, 1, 4);
        parcel.writeInt(this.a ? 1 : 0);
        P p = this.b;
        AbstractC3489l3.e(parcel, 2, p == null ? null : p.asBinder());
        AbstractC3489l3.e(parcel, 3, this.c);
        AbstractC3489l3.o(iN, parcel);
    }
}
