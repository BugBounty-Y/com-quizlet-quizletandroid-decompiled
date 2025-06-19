package com.google.android.gms.ads;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1602k;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.G;
import com.google.android.gms.ads.internal.client.H0;
import com.google.android.gms.ads.internal.client.I0;
import com.google.android.gms.ads.internal.client.O0;
import com.google.android.gms.ads.internal.client.zzr;
import com.google.android.gms.internal.ads.BinderC1869b9;
import com.google.android.gms.internal.ads.BinderC2739va;

/* loaded from: classes2.dex */
public final class e {
    public final Context a;
    public final G b;

    public e(Context context, String str) {
        com.google.android.gms.common.internal.u.i(context, "context cannot be null");
        C1608n c1608n = C1614q.f.b;
        BinderC2739va binderC2739va = new BinderC2739va();
        c1608n.getClass();
        G g = (G) new C1602k(c1608n, context, str, binderC2739va).d(context, false);
        this.a = context;
        this.b = g;
    }

    public final f a() {
        Context context = this.a;
        try {
            return new f(context, this.b.zze());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Failed to build AdLoader.", e);
            return new f(context, new H0(new I0()));
        }
    }

    public final void b(com.google.android.gms.ads.formats.c cVar, h... hVarArr) {
        if (hVarArr == null || hVarArr.length <= 0) {
            throw new IllegalArgumentException("The supported ad sizes must contain at least one valid ad size.");
        }
        try {
            this.b.m3(new BinderC1869b9(cVar), new zzr(this.a, hVarArr));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to add Google Ad Manager banner ad listener", e);
        }
    }

    public final void c(d dVar) {
        try {
            this.b.U2(new O0(dVar));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to set AdListener.", e);
        }
    }
}
