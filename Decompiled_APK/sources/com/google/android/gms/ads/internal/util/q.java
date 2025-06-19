package com.google.android.gms.ads.internal.util;

import android.content.Context;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.ads.zzapc;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class q {
    public static C3 a;
    public static final Object b = new Object();

    public q(Context context) {
        C3 c3;
        context = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        synchronized (b) {
            try {
                if (a == null) {
                    AbstractC2773w7.a(context);
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.x4)).booleanValue()) {
                        c3 = l.m(context);
                    } else {
                        c3 = new C3(new com.android.volley.toolbox.d(new C1732Mb(context.getApplicationContext())), new C1732Mb(new C1(23)));
                        c3.g();
                    }
                    a = c3;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static o a(int i, String str, HashMap map, byte[] bArr) {
        o oVar = new o();
        com.quizlet.data.repository.widget.b bVar = new com.quizlet.data.repository.widget.b(str, false, oVar, 8);
        com.google.android.gms.ads.internal.util.client.f fVar = new com.google.android.gms.ads.internal.util.client.f();
        n nVar = new n(i, str, oVar, bVar, bArr, map, fVar);
        if (com.google.android.gms.ads.internal.util.client.f.c()) {
            try {
                Map mapC = nVar.c();
                byte[] bArr2 = bArr == null ? null : bArr;
                if (com.google.android.gms.ads.internal.util.client.f.c()) {
                    fVar.d("onNetworkRequest", new com.quizlet.data.repository.classmembership.c(str, "GET", mapC, bArr2));
                }
            } catch (zzapc e) {
                com.google.android.gms.ads.internal.util.client.i.h(e.getMessage());
            }
        }
        a.e(nVar);
        return oVar;
    }
}
