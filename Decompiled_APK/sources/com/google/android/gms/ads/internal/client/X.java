package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* loaded from: classes2.dex */
public abstract class X extends AbstractBinderC2814x5 implements Y {
    public static Y asInterface(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.ILiteSdkInfo");
        return iInterfaceQueryLocalInterface instanceof Y ? (Y) iInterfaceQueryLocalInterface : new W(iBinder, "com.google.android.gms.ads.internal.client.ILiteSdkInfo", 0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            zzex liteSdkVersion = getLiteSdkVersion();
            parcel2.writeNoException();
            AbstractC2857y5.d(parcel2, liteSdkVersion);
            return true;
        }
        if (i != 2) {
            return false;
        }
        InterfaceC2825xa adapterCreator = getAdapterCreator();
        parcel2.writeNoException();
        AbstractC2857y5.e(parcel2, adapterCreator);
        return true;
    }
}
