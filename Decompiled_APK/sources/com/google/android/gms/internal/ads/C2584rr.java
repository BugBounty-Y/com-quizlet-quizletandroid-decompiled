package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;

/* renamed from: com.google.android.gms.internal.ads.rr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2584rr {
    public final Context a;
    public final Xv b;
    public final Yv c;
    public final com.google.android.gms.ads.internal.util.client.k d;
    public final C2499pr e;
    public final Uq f;

    public C2584rr(Context context, Xv xv, Yv yv, com.google.android.gms.ads.internal.util.client.k kVar, C2499pr c2499pr, Uq uq) {
        this.a = context;
        this.b = xv;
        this.c = yv;
        this.d = kVar;
        this.e = c2499pr;
        this.f = uq;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void a(String str, com.google.android.gms.auth.api.signin.internal.h hVar, Tq tq, Ah ah) {
        com.google.common.util.concurrent.e eVarD;
        Pq pqF = null;
        if (Uq.a() && ((Boolean) R7.d.o()).booleanValue()) {
            pqF = LA.f(this.a, 14);
            pqF.zzi();
        }
        Yv yv = this.c;
        if (hVar != null) {
            try {
                eVarD = new com.google.firebase.messaging.u((com.google.android.gms.ads.internal.util.client.h) hVar.b, this.d, yv, this.e).k(1, 0L, str);
            } catch (NullPointerException | RejectedExecutionException unused) {
                eVarD = AbstractC2025es.E(com.google.android.gms.ads.internal.util.client.j.b);
            }
        } else {
            eVarD = ((C2227jd) yv).d(new A4(10, this, str));
        }
        eVarD.a(new Qv(0, eVarD, new com.quizlet.data.interactor.progress.c(this, pqF, tq, ah)), this.b);
    }

    public final void b(List list, com.google.android.gms.auth.api.signin.internal.h hVar) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            a((String) it2.next(), hVar, null, null);
        }
    }
}
