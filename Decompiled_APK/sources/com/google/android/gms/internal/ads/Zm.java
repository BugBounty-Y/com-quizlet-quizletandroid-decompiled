package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* loaded from: classes2.dex */
public final class Zm implements InterfaceC2751vm {
    public final C1759Qe a;
    public final C2227jd b;
    public final com.quizlet.data.repository.classmembership.c c;
    public final C2412nq d;
    public final C1974dk e;
    public final Ek f;
    public final VersionInfoParcel g;
    public final Context h;

    public Zm(C1759Qe c1759Qe, C2227jd c2227jd, com.quizlet.data.repository.classmembership.c cVar, C2412nq c2412nq, C1974dk c1974dk, Ek ek, VersionInfoParcel versionInfoParcel, Context context, L9 l9) {
        this.g = versionInfoParcel;
        this.h = context;
        this.a = c1759Qe;
        this.b = c2227jd;
        this.c = cVar;
        this.d = c2412nq;
        this.e = c1974dk;
        this.f = ek;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        Yp yp = vp.s;
        return (yp == null || yp.c == null) ? false : true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j2)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, this.f.d, "rendering-native-ads-native-js-webview-start");
        }
        com.google.common.util.concurrent.e eVarA = this.d.a();
        C2439oa c2439oa = new C2439oa(11, this, vp);
        C2227jd c2227jd = this.b;
        return AbstractC2025es.N(AbstractC2025es.N(eVarA, c2439oa, c2227jd), new C2616sg(this, c1849aq, vp, 8), c2227jd);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:117:0x03eb  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x03fb  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x04f6  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x04f9  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x0570  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0158  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0201  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0206  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0265  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0267  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0273  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0332  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0368 A[EDGE_INSN: B:165:0x0368->B:99:0x0368 BREAK  A[LOOP:0: B:101:0x036c->B:113:0x03cc], PHI: r21
  0x0368: PHI (r21v5 com.google.android.gms.internal.ads.Ek) = 
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v11 com.google.android.gms.internal.ads.Ek)
  (r21v11 com.google.android.gms.internal.ads.Ek)
  (r21v11 com.google.android.gms.internal.ads.Ek)
 binds: [B:92:0x034e, B:94:0x0354, B:96:0x0360, B:98:0x0366, B:165:0x0368, B:162:0x0368, B:108:0x0390] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0368 A[PHI: r21
  0x0368: PHI (r21v5 com.google.android.gms.internal.ads.Ek) = 
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v4 com.google.android.gms.internal.ads.Ek)
  (r21v11 com.google.android.gms.internal.ads.Ek)
  (r21v11 com.google.android.gms.internal.ads.Ek)
  (r21v11 com.google.android.gms.internal.ads.Ek)
 binds: [B:92:0x034e, B:94:0x0354, B:96:0x0360, B:98:0x0366, B:165:0x0368, B:162:0x0368, B:108:0x0390] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.Jv c(final com.google.android.gms.internal.ads.C1849aq r31, final com.google.android.gms.internal.ads.Vp r32, final org.json.JSONObject r33) {
        /*
            Method dump skipped, instructions count: 1489
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Zm.c(com.google.android.gms.internal.ads.aq, com.google.android.gms.internal.ads.Vp, org.json.JSONObject):com.google.android.gms.internal.ads.Jv");
    }
}
