package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.C2355mc;
import com.google.android.gms.internal.ads.C2612sc;
import com.google.android.gms.internal.ads.InterfaceC2441oc;

/* renamed from: com.google.android.gms.ads.internal.client.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1584b extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ String c;
    public final /* synthetic */ BinderC2739va d;

    public C1584b(Context context, String str, BinderC2739va binderC2739va) {
        this.b = context;
        this.c = str;
        this.d = binderC2739va;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.b, "rewarded");
        return new M0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.x2(new com.google.android.gms.dynamic.b(this.b), this.c, this.d, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        C2612sc c2612sc;
        IBinder iBinderH4;
        String str = this.c;
        BinderC2739va binderC2739va = this.d;
        Context context = this.b;
        com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
        try {
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.rewarded.ChimeraRewardedAdCreatorImpl");
                if (iBinderB == null) {
                    c2612sc = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAdCreator");
                    c2612sc = iInterfaceQueryLocalInterface instanceof C2612sc ? (C2612sc) iInterfaceQueryLocalInterface : new C2612sc(iBinderB, "com.google.android.gms.ads.internal.rewarded.client.IRewardedAdCreator", 0);
                }
                iBinderH4 = c2612sc.h4(bVar, str, binderC2739va);
            } catch (Exception e) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e);
            }
        } catch (RemoteException e2) {
            e = e2;
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            return null;
        } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
            e = e3;
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            return null;
        }
        if (iBinderH4 == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface2 = iBinderH4.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAd");
        return iInterfaceQueryLocalInterface2 instanceof InterfaceC2441oc ? (InterfaceC2441oc) iInterfaceQueryLocalInterface2 : new C2355mc(iBinderH4);
    }
}
