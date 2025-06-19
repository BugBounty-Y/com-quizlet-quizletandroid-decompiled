package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* loaded from: classes2.dex */
public final class N0 extends AbstractBinderC2814x5 implements InterfaceC1609n0 {
    public N0() {
        super("com.google.android.gms.ads.internal.client.IOnPaidEventListener");
    }

    public static InterfaceC1609n0 e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IOnPaidEventListener");
        return iInterfaceQueryLocalInterface instanceof InterfaceC1609n0 ? (InterfaceC1609n0) iInterfaceQueryLocalInterface : new C1607m0(iBinder);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1609n0
    public final void R2(zzt zztVar) {
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            AbstractC2857y5.b(parcel);
            parcel2.writeNoException();
            return true;
        }
        if (i != 2) {
            return false;
        }
        parcel2.writeNoException();
        ClassLoader classLoader = AbstractC2857y5.a;
        parcel2.writeInt(1);
        return true;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1609n0
    public final boolean f() {
        return true;
    }
}
