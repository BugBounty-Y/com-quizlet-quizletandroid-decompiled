package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.ads.mediation.admob.AdMobAdapter;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.vn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2752vn implements InterfaceC2751vm {
    public final /* synthetic */ int a;
    public final Xv b;
    public final Lq c;
    public final Object d;
    public final Object e;

    public /* synthetic */ C2752vn(Lq lq, Xv xv, Object obj, Object obj2, int i) {
        this.a = i;
        this.c = lq;
        this.b = xv;
        this.e = obj2;
        this.d = obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        Yp yp;
        switch (this.a) {
            case 0:
                return !vp.t.isEmpty();
            default:
                return (((D7) this.d) == null || (yp = vp.s) == null || yp.a == null) ? false : true;
        }
    }

    /* JADX WARN: Type inference failed for: r6v0, types: [com.google.android.gms.internal.ads.qh, com.google.android.gms.internal.ads.x5] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        C2880ym c2880ymA;
        switch (this.a) {
            case 0:
                Iterator it2 = vp.t.iterator();
                while (true) {
                    if (it2.hasNext()) {
                        try {
                            c2880ymA = ((InterfaceC2837xm) this.d).a((String) it2.next(), vp.v);
                        } catch (zzfcw unused) {
                        }
                    } else {
                        c2880ymA = null;
                    }
                }
                C2880ym c2880ym = c2880ymA;
                if (c2880ym == null) {
                    return AbstractC2025es.C(new zzegc(3, "Unable to instantiate mediation adapter class."));
                }
                C2313ld c2313ld = new C2313ld();
                c2880ym.c.f0(new com.bumptech.glide.manager.p(c2880ym, c2313ld));
                if (vp.M) {
                    Bundle bundle = ((C2023eq) c1849aq.a.b).d.m;
                    Bundle bundle2 = bundle.getBundle(AdMobAdapter.class.getName());
                    if (bundle2 == null) {
                        bundle2 = new Bundle();
                        bundle.putBundle(AdMobAdapter.class.getName(), bundle2);
                    }
                    bundle2.putBoolean("render_test_ad_label", true);
                }
                Jq jq = Jq.ADAPTER_LOAD_AD_SYN;
                com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d();
                dVar.a = this;
                dVar.b = c1849aq;
                dVar.c = vp;
                dVar.d = c2880ym;
                CallableC2154hp callableC2154hp = new CallableC2154hp(dVar, 2);
                Tv tv = Lq.d;
                List list = Collections.EMPTY_LIST;
                com.google.common.util.concurrent.e eVarD = ((C2227jd) this.b).d(callableC2154hp);
                Lq lq = this.c;
                C2084g6 c2084g6 = new C2084g6(lq, jq, null, tv, list, eVarD);
                C2084g6 c2084g6A = lq.a(c2084g6.b(), Jq.ADAPTER_LOAD_AD_ACK);
                C2846xv c2846xvN = AbstractC2025es.N((com.google.common.util.concurrent.e) c2084g6A.e, new C2525qa(1, c2313ld), AbstractC2270kd.g);
                com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) c2084g6A.b;
                List list2 = (List) c2084g6A.d;
                Lq lq2 = (Lq) c2084g6A.f;
                C2084g6 c2084g62 = new C2084g6(lq2, c2084g6A.c, (String) c2084g6A.a, eVar, list2, c2846xvN);
                return lq2.a(c2084g62.b(), Jq.ADAPTER_WRAP_ADAPTER).k(new com.quizlet.data.repository.user.e(this, c1849aq, vp, c2880ym, 3)).b();
            default:
                C2313ld c2313ld2 = new C2313ld();
                Os os = new Os(25);
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = new com.quizlet.data.repository.studysetwithcreatorinclass.g(this, c2313ld2, c1849aq, vp, os);
                synchronized (os) {
                    os.b = gVar;
                }
                Yp yp = vp.s;
                C7 c7 = new C7(os, yp.b, yp.a);
                Jq jq2 = Jq.CUSTOM_RENDER_SYN;
                C1732Mb c1732Mb = new C1732Mb(29, this, c7);
                Lq lq3 = this.c;
                Xv xv = this.b;
                C2084g6 c2084g63 = new C2084g6(lq3, jq2, null, Lq.d, Collections.EMPTY_LIST, ((C2227jd) xv).d(new CallableC2154hp(c1732Mb, 2)));
                C2084g6 c2084g6A2 = lq3.a(c2084g63.b(), Jq.CUSTOM_RENDER_ACK);
                C2846xv c2846xvN2 = AbstractC2025es.N((com.google.common.util.concurrent.e) c2084g6A2.e, new C2525qa(1, c2313ld2), AbstractC2270kd.g);
                return new C2084g6((Lq) c2084g6A2.f, c2084g6A2.c, (String) c2084g6A2.a, (com.google.common.util.concurrent.e) c2084g6A2.b, (List) c2084g6A2.d, c2846xvN2).b();
        }
    }
}
