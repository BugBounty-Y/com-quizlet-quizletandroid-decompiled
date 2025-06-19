package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.RemoteException;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.google.android.gms.ads.internal.client.C1584b;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;

/* renamed from: com.google.android.gms.internal.ads.Bc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1667Bc {
    public final InterfaceC2441oc a;
    public final Context b;
    public final BinderC1661Ac c;
    public final long d = System.currentTimeMillis();

    public C1667Bc(Context context, String str) {
        this.b = context.getApplicationContext();
        C1608n c1608n = C1614q.f.b;
        BinderC2739va binderC2739va = new BinderC2739va();
        c1608n.getClass();
        this.a = (InterfaceC2441oc) new C1584b(context, str, binderC2739va).d(context, false);
        this.c = new BinderC1661Ac();
    }

    public static void a(Context context, String str, com.google.android.gms.ads.g gVar, C2578rl c2578rl) {
        com.google.android.gms.common.internal.u.i(context, "Context cannot be null.");
        com.google.android.gms.common.internal.u.i(str, "AdUnitId cannot be null.");
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        AbstractC2773w7.a(context);
        if (((Boolean) U7.k.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new RunnableC0069f(8, context, str, gVar, c2578rl, false));
                return;
            }
        }
        new C1667Bc(context, str).b(gVar.zza(), c2578rl);
    }

    public final void b(com.google.android.gms.ads.internal.client.y0 y0Var, C2578rl c2578rl) {
        try {
            InterfaceC2441oc interfaceC2441oc = this.a;
            if (interfaceC2441oc != null) {
                y0Var.n = this.d;
                interfaceC2441oc.C2(com.google.android.gms.ads.internal.client.R0.a(this.b, y0Var), new BinderC2870yc(c2578rl, this, 1));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }
}
