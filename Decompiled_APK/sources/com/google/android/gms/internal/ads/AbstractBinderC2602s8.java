package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.s8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC2602s8 extends AbstractBinderC2814x5 implements InterfaceC2645t8 {
    public static InterfaceC2645t8 e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IAttributionInfo");
        return iInterfaceQueryLocalInterface instanceof InterfaceC2645t8 ? (InterfaceC2645t8) iInterfaceQueryLocalInterface : new C2559r8(iBinder);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 2) {
            parcel2.writeNoException();
            parcel2.writeString(((BinderC2388n8) this).a);
            return true;
        }
        if (i != 3) {
            return false;
        }
        ArrayList arrayList = ((BinderC2388n8) this).c;
        parcel2.writeNoException();
        parcel2.writeList(arrayList);
        return true;
    }
}
