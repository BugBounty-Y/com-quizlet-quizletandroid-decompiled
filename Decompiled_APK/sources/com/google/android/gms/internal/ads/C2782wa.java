package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.wa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2782wa extends AbstractC2771w5 implements InterfaceC2825xa {
    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final InterfaceC1965db A(String str) {
        InterfaceC1965db c1921cb;
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        Parcel parcelY3 = Y3(3, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        int i = BinderC2140hb.b;
        if (strongBinder == null) {
            c1921cb = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IRtbAdapter");
            c1921cb = iInterfaceQueryLocalInterface instanceof InterfaceC1965db ? (InterfaceC1965db) iInterfaceQueryLocalInterface : new C1921cb(strongBinder, "com.google.android.gms.ads.internal.mediation.client.rtb.IRtbAdapter", 0);
        }
        parcelY3.recycle();
        return c1921cb;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final InterfaceC2911za C(String str) {
        InterfaceC2911za c2868ya;
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        Parcel parcelY3 = Y3(1, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c2868ya = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapter");
            c2868ya = iInterfaceQueryLocalInterface instanceof InterfaceC2911za ? (InterfaceC2911za) iInterfaceQueryLocalInterface : new C2868ya(strongBinder, "com.google.android.gms.ads.internal.mediation.client.IMediationAdapter", 0);
        }
        parcelY3.recycle();
        return c2868ya;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final boolean I(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        Parcel parcelY3 = Y3(4, parcelF3);
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2825xa
    public final boolean R(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        Parcel parcelY3 = Y3(2, parcelF3);
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }
}
