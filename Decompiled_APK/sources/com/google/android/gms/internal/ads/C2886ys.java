package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;

/* renamed from: com.google.android.gms.internal.ads.ys, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2886ys extends com.google.android.gms.ads.internal.b {
    public final int z;

    public C2886ys(int i, Context context, Looper looper, InterfaceC1652b interfaceC1652b, InterfaceC1653c interfaceC1653c) {
        super(116, context, looper, interfaceC1652b, interfaceC1653c);
        this.z = i;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return this.z;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.gass.internal.IGassService");
        return iInterfaceQueryLocalInterface instanceof C2929zs ? (C2929zs) iInterfaceQueryLocalInterface : new C2929zs(iBinder, "com.google.android.gms.gass.internal.IGassService", 0);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.gass.internal.IGassService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.gass.START";
    }
}
