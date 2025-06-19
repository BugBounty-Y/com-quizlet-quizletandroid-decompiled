package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;

/* loaded from: classes2.dex */
public final class E0 extends AbstractBinderC2814x5 implements InterfaceC1595g0 {
    public final String a;
    public final String b;

    public E0(String str, String str2) {
        super("com.google.android.gms.ads.internal.client.IMuteThisAdReason");
        this.a = str;
        this.b = str2;
    }

    public static InterfaceC1595g0 e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IMuteThisAdReason");
        return iInterfaceQueryLocalInterface instanceof InterfaceC1595g0 ? (InterfaceC1595g0) iInterfaceQueryLocalInterface : new C1593f0(iBinder, "com.google.android.gms.ads.internal.client.IMuteThisAdReason", 0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            parcel2.writeNoException();
            parcel2.writeString(this.a);
            return true;
        }
        if (i != 2) {
            return false;
        }
        parcel2.writeNoException();
        parcel2.writeString(this.b);
        return true;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1595g0
    public final String f() {
        return this.b;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1595g0
    public final String zze() {
        return this.a;
    }
}
