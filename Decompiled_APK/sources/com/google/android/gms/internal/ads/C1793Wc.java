package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;

/* renamed from: com.google.android.gms.internal.ads.Wc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1793Wc extends AbstractC2771w5 implements InterfaceC1805Yc {
    public final InterfaceC1787Vc h4(com.google.android.gms.dynamic.b bVar, BinderC2739va binderC2739va) {
        InterfaceC1787Vc c1775Tc;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        AbstractC2857y5.e(parcelF3, binderC2739va);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(2, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1775Tc = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.signals.ISignalGenerator");
            c1775Tc = iInterfaceQueryLocalInterface instanceof InterfaceC1787Vc ? (InterfaceC1787Vc) iInterfaceQueryLocalInterface : new C1775Tc(strongBinder);
        }
        parcelY3.recycle();
        return c1775Tc;
    }
}
