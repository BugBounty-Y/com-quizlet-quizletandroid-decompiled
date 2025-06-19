package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractBinderC2869yb;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.C2826xb;
import com.google.android.gms.internal.ads.InterfaceC2912zb;

/* renamed from: com.google.android.gms.ads.internal.client.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1592f extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ BinderC2739va c;

    public C1592f(Context context, BinderC2739va binderC2739va) {
        this.b = context;
        this.c = binderC2739va;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object a() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.D1(new com.google.android.gms.dynamic.b(this.b), this.c, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        InterfaceC2912zb c2826xb;
        Context context = this.b;
        com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
        try {
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.DynamiteOfflineUtilsCreatorImpl");
                int i = AbstractBinderC2869yb.a;
                if (iBinderB == null) {
                    c2826xb = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.offline.IOfflineUtilsCreator");
                    c2826xb = iInterfaceQueryLocalInterface instanceof InterfaceC2912zb ? (InterfaceC2912zb) iInterfaceQueryLocalInterface : new C2826xb(iBinderB, "com.google.android.gms.ads.internal.offline.IOfflineUtilsCreator", 0);
                }
                return ((C2826xb) c2826xb).h4(bVar, this.c);
            } catch (Exception e) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e);
            }
        } catch (RemoteException | com.google.android.gms.ads.internal.util.client.zzr | NullPointerException unused) {
            return null;
        }
    }
}
