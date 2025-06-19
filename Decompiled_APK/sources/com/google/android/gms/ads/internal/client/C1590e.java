package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractBinderC1799Xc;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.C1793Wc;
import com.google.android.gms.internal.ads.InterfaceC1805Yc;

/* renamed from: com.google.android.gms.ads.internal.client.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1590e extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ BinderC2739va c;

    public C1590e(Context context, BinderC2739va binderC2739va) {
        this.b = context;
        this.c = binderC2739va;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object a() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.u3(new com.google.android.gms.dynamic.b(this.b), this.c, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        IInterface c1793Wc;
        Context context = this.b;
        com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
        try {
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.DynamiteSignalGeneratorCreatorImpl");
                int i = AbstractBinderC1799Xc.a;
                if (iBinderB == null) {
                    c1793Wc = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.signals.ISignalGeneratorCreator");
                    c1793Wc = iInterfaceQueryLocalInterface instanceof InterfaceC1805Yc ? (InterfaceC1805Yc) iInterfaceQueryLocalInterface : new C1793Wc(iBinderB, "com.google.android.gms.ads.internal.signals.ISignalGeneratorCreator", 0);
                }
                return ((C1793Wc) c1793Wc).h4(bVar, this.c);
            } catch (Exception e) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e);
            }
        } catch (RemoteException | com.google.android.gms.ads.internal.util.client.zzr | NullPointerException unused) {
            return null;
        }
    }
}
