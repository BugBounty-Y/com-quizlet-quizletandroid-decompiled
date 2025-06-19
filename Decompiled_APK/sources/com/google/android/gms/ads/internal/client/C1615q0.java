package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.BinderC2739va;

/* renamed from: com.google.android.gms.ads.internal.client.q0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1615q0 extends AbstractC2771w5 {
    public final InterfaceC1613p0 h4(com.google.android.gms.dynamic.b bVar, BinderC2739va binderC2739va) {
        InterfaceC1613p0 c1611o0;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        AbstractC2857y5.e(parcelF3, binderC2739va);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(1, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1611o0 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IOutOfContextTester");
            c1611o0 = iInterfaceQueryLocalInterface instanceof InterfaceC1613p0 ? (InterfaceC1613p0) iInterfaceQueryLocalInterface : new C1611o0(strongBinder);
        }
        parcelY3.recycle();
        return c1611o0;
    }
}
