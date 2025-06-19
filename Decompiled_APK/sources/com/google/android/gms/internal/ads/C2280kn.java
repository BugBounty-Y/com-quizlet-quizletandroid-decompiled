package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.zzv;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.kn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2280kn implements Fv {
    public final Lq a;
    public final Zg b;
    public final C2542qr c;
    public final C2584rr d;
    public final Xv e;
    public final ScheduledExecutorService f;
    public final InterfaceC2488pg g;
    public final C2195in h;
    public final C2923zm i;
    public final Context j;
    public final Tq k;
    public final com.google.android.datatransport.cct.internal.s l;
    public final Ek m;

    public C2280kn(Context context, Lq lq, C2195in c2195in, Zg zg, C2542qr c2542qr, C2584rr c2584rr, InterfaceC2488pg interfaceC2488pg, Xv xv, ScheduledExecutorService scheduledExecutorService, C2923zm c2923zm, Tq tq, com.google.android.datatransport.cct.internal.s sVar, Ek ek) {
        this.j = context;
        this.a = lq;
        this.h = c2195in;
        this.b = zg;
        this.c = c2542qr;
        this.d = c2584rr;
        this.g = interfaceC2488pg;
        this.e = xv;
        this.f = scheduledExecutorService;
        this.i = c2923zm;
        this.k = tq;
        this.l = sVar;
        this.m = ek;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x004c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String a(com.google.android.gms.internal.ads.C1849aq r6) {
        /*
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.B5
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r2 = r1.c
            java.lang.Object r0 = r2.a(r0)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            r2 = 1
            java.lang.String r3 = "No fill."
            if (r2 == r0) goto L18
            java.lang.String r0 = "No ad config."
            goto L19
        L18:
            r0 = r3
        L19:
            androidx.work.impl.model.n r6 = r6.b
            java.lang.Object r6 = r6.b
            com.google.android.gms.internal.ads.Xp r6 = (com.google.android.gms.internal.ads.Xp) r6
            int r2 = r6.f
            if (r2 == 0) goto L4c
            r4 = 200(0xc8, float:2.8E-43)
            r5 = 300(0x12c, float:4.2E-43)
            if (r2 < r4) goto L3c
            if (r2 >= r5) goto L3c
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.A5
            com.google.android.gms.internal.ads.u7 r1 = r1.c
            java.lang.Object r1 = r1.a(r2)
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 != 0) goto L4c
            goto L4d
        L3c:
            if (r2 < r5) goto L45
            r0 = 400(0x190, float:5.6E-43)
            if (r2 >= r0) goto L45
            java.lang.String r3 = "No location header to follow redirect or too many redirects."
            goto L4d
        L45:
            java.lang.String r0 = "Received error HTTP response code: "
            java.lang.String r3 = android.support.v4.media.session.a.f(r2, r0)
            goto L4d
        L4c:
            r3 = r0
        L4d:
            com.google.android.gms.internal.ads.Gw r6 = r6.j
            if (r6 == 0) goto L54
            java.lang.String r6 = r6.b
            return r6
        L54:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2280kn.a(com.google.android.gms.internal.ads.aq):java.lang.String");
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        com.google.common.util.concurrent.e eVarB;
        int i;
        Bundle bundle;
        C2280kn c2280kn = this;
        C1849aq c1849aq = (C1849aq) obj;
        C2601s7 c2601s7 = AbstractC2773w7.h2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && (bundle = (Bundle) c1849aq.b.d) != null) {
            c2280kn.m.d.putAll(bundle);
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.i2)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, c2280kn.m.d, "rendering-start");
        }
        String strA = a(c1849aq);
        C2923zm c2923zm = c2280kn.i;
        androidx.work.impl.model.n nVar = c1849aq.b;
        Xp xp = (Xp) nVar.b;
        c2923zm.d = xp;
        if (((Boolean) rVar.c.a(AbstractC2773w7.o8)).booleanValue() && (i = xp.f) != 0 && (i < 200 || i >= 300)) {
            return AbstractC2025es.C(new zzegy(3, strA));
        }
        String str = xp.q;
        if (!((Boolean) rVar.c.a(AbstractC2773w7.I3)).booleanValue() || TextUtils.isEmpty(str)) {
            for (Vp vp : (List) nVar.a) {
                c2923zm.c(vp, c2923zm.a.size());
                Iterator it2 = vp.a.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        c2923zm.d(vp, 0L, AbstractC1972di.x(1, null, null), false);
                        break;
                    }
                    InterfaceC2751vm interfaceC2751vmA = c2280kn.g.a(vp.b, (String) it2.next());
                    if (interfaceC2751vmA == null || !interfaceC2751vmA.a(c1849aq, vp)) {
                    }
                }
            }
        } else {
            List list = (List) nVar.a;
            synchronized (c2923zm) {
                Map map = c2923zm.b;
                if (map.containsKey(str)) {
                    zzv zzvVar = (zzv) map.get(str);
                    List list2 = c2923zm.a;
                    int iIndexOf = list2.indexOf(zzvVar);
                    try {
                        list2.remove(iIndexOf);
                    } catch (IndexOutOfBoundsException e) {
                        com.google.android.gms.ads.internal.j.C.h.h("AdapterResponseInfoCollector.replaceAdapterResponseInfoEntry", e);
                    }
                    c2923zm.b.remove(str);
                    Iterator it3 = list.iterator();
                    while (it3.hasNext()) {
                        c2923zm.c((Vp) it3.next(), iIndexOf);
                        iIndexOf++;
                    }
                }
            }
        }
        Zg zg = c2280kn.b;
        C1664Af c1664Af = new C1664Af(c1849aq, c2280kn.d, c2280kn.c);
        Xv xv = c2280kn.e;
        zg.i1(c1664Af, xv);
        if (xp.r > 1) {
            com.google.android.datatransport.cct.internal.s sVar = c2280kn.l;
            synchronized (sVar) {
                try {
                    if (!((AtomicBoolean) sVar.a).getAndSet(true)) {
                        List list3 = (List) c1849aq.b.a;
                        if (list3.isEmpty()) {
                            ((C1985dw) sVar.g).h(new zzegy(3, a(c1849aq)));
                        } else {
                            sVar.i = c1849aq;
                            C2195in c2195in = (C2195in) sVar.e;
                            sVar.h = new C1890bn(c1849aq, c2195in, (C1985dw) sVar.g);
                            c2195in.c(list3);
                            for (Vp vpA = ((C1890bn) sVar.h).a(); vpA != null; vpA = ((C1890bn) sVar.h).a()) {
                                sVar.u(vpA);
                            }
                        }
                    }
                    eVarB = (C1985dw) sVar.g;
                } finally {
                }
            }
        } else {
            String strA2 = a(c1849aq);
            Lq lq = c2280kn.a;
            eVarB = new C2084g6(lq, Jq.RENDER_CONFIG_INIT, null, Lq.d, Collections.EMPTY_LIST, AbstractC2025es.C(new zzegy(3, strA2))).b();
            C2195in c2195in2 = c2280kn.h;
            synchronized (c2195in2) {
                c2195in2.i = c2195in2.a.elapsedRealtime();
            }
            int i2 = 0;
            for (Vp vp2 : (List) nVar.a) {
                Iterator it4 = vp2.a.iterator();
                while (true) {
                    if (!it4.hasNext()) {
                        break;
                    }
                    String str2 = (String) it4.next();
                    InterfaceC2751vm interfaceC2751vmA2 = c2280kn.g.a(vp2.b, str2);
                    if (interfaceC2751vmA2 != null && interfaceC2751vmA2.a(c1849aq, vp2)) {
                        C2084g6 c2084g6A = lq.a(eVarB, Jq.RENDER_CONFIG_WATERFALL);
                        Lq lq2 = (Lq) c2084g6A.f;
                        eVarB = new C2084g6(lq2, c2084g6A.c, "render-config-" + i2 + "-" + str2, (com.google.common.util.concurrent.e) c2084g6A.b, (List) c2084g6A.d, AbstractC2025es.A((com.google.common.util.concurrent.e) c2084g6A.e, Throwable.class, new com.google.android.gms.ads.internal.c(c2280kn, vp2, c1849aq, interfaceC2751vmA2, 5), lq2.a)).b();
                        break;
                    }
                    c2280kn = this;
                }
                i2++;
                c2280kn = this;
            }
            eVarB.a(new RunnableC2104gj(c2195in2, 7), xv);
        }
        return eVarB;
    }
}
