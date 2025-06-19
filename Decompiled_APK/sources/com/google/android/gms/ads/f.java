package com.google.android.gms.ads;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.ads.internal.client.D;
import com.google.android.gms.ads.internal.client.R0;
import com.google.android.gms.ads.internal.client.y0;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.U7;

/* loaded from: classes2.dex */
public final class f {
    public final Context a;
    public final D b;

    public f(Context context, D d) {
        this.a = context;
        this.b = d;
    }

    public final void a(g gVar) {
        c(gVar.zza);
    }

    public final void b(AdManagerAdRequest adManagerAdRequest) {
        c(adManagerAdRequest.zza);
    }

    public final void c(y0 y0Var) {
        Context context = this.a;
        AbstractC2773w7.a(context);
        if (((Boolean) U7.c.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new v(1, this, y0Var));
                return;
            }
        }
        try {
            this.b.D0(R0.a(context, y0Var));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Failed to load ad.", e);
        }
    }
}
