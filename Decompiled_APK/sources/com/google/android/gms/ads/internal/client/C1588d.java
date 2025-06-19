package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.ads.OutOfContextTestingActivity;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.C1744Ob;

/* renamed from: com.google.android.gms.ads.internal.client.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1588d extends AbstractC1612p {
    public final /* synthetic */ OutOfContextTestingActivity b;
    public final /* synthetic */ BinderC2739va c;

    public C1588d(OutOfContextTestingActivity outOfContextTestingActivity, BinderC2739va binderC2739va) {
        this.b = outOfContextTestingActivity;
        this.c = binderC2739va;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object a() {
        C1608n.y(this.b, "out_of_context_tester");
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        OutOfContextTestingActivity outOfContextTestingActivity = this.b;
        com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(outOfContextTestingActivity);
        AbstractC2773w7.a(outOfContextTestingActivity);
        if (((Boolean) r.d.c.a(AbstractC2773w7.t9)).booleanValue()) {
            return s.G2(bVar, this.c, ModuleDescriptor.MODULE_VERSION);
        }
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        C1615q0 c1615q0;
        OutOfContextTestingActivity outOfContextTestingActivity = this.b;
        com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(outOfContextTestingActivity);
        AbstractC2773w7.a(outOfContextTestingActivity);
        if (((Boolean) r.d.c.a(AbstractC2773w7.t9)).booleanValue()) {
            try {
                try {
                    IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(outOfContextTestingActivity).b("com.google.android.gms.ads.DynamiteOutOfContextTesterCreatorImpl");
                    if (iBinderB == null) {
                        c1615q0 = null;
                    } else {
                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.client.IOutOfContextTesterCreator");
                        c1615q0 = iInterfaceQueryLocalInterface instanceof C1615q0 ? (C1615q0) iInterfaceQueryLocalInterface : new C1615q0(iBinderB, "com.google.android.gms.ads.internal.client.IOutOfContextTesterCreator", 0);
                    }
                    return c1615q0.h4(bVar, this.c);
                } catch (Exception e) {
                    throw new com.google.android.gms.ads.internal.util.client.zzr(e);
                }
            } catch (RemoteException e2) {
                e = e2;
                C1744Ob.a(outOfContextTestingActivity).d("ClientApiBroker.getOutOfContextTester", e);
                return null;
            } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
                e = e3;
                C1744Ob.a(outOfContextTestingActivity).d("ClientApiBroker.getOutOfContextTester", e);
                return null;
            } catch (NullPointerException e4) {
                e = e4;
                C1744Ob.a(outOfContextTestingActivity).d("ClientApiBroker.getOutOfContextTester", e);
                return null;
            }
        }
        return null;
    }
}
