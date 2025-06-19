package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;

/* renamed from: com.google.android.gms.internal.ads.xb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2826xb extends AbstractC2771w5 implements InterfaceC2912zb {
    public final InterfaceC2783wb h4(com.google.android.gms.dynamic.b bVar, BinderC2739va binderC2739va) {
        InterfaceC2783wb c2740vb;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        AbstractC2857y5.e(parcelF3, binderC2739va);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(1, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c2740vb = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.offline.IOfflineUtils");
            c2740vb = iInterfaceQueryLocalInterface instanceof InterfaceC2783wb ? (InterfaceC2783wb) iInterfaceQueryLocalInterface : new C2740vb(strongBinder);
        }
        parcelY3.recycle();
        return c2740vb;
    }
}
