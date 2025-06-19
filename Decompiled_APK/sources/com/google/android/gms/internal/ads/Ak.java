package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class Ak implements Ph, InterfaceC1582a, InterfaceC2189ih, InterfaceC1884bh, Dh {
    public final Context a;
    public final C2283kq b;
    public final Hk c;
    public final C1849aq d;
    public final Vp e;
    public final C2107gm f;
    public final String g;
    public Boolean i;
    public long h = -1;
    public final AtomicBoolean k = new AtomicBoolean(false);
    public final AtomicBoolean l = new AtomicBoolean(false);
    public final boolean j = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K6)).booleanValue();

    public Ak(Context context, C2283kq c2283kq, Hk hk, C1849aq c1849aq, Vp vp, C2107gm c2107gm, String str) {
        this.a = context;
        this.b = c2283kq;
        this.c = hk;
        this.d = c1849aq;
        this.e = vp;
        this.f = c2107gm;
        this.g = str;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1884bh
    public final void E(zzdgh zzdghVar) {
        if (this.j) {
            Fi fiA = a("ifts");
            fiA.o("reason", "exception");
            if (!TextUtils.isEmpty(zzdghVar.getMessage())) {
                fiA.o("msg", zzdghVar.getMessage());
            }
            fiA.x();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        if (r() || this.e.b()) {
            Fi fiA = a("impression");
            if (this.h > 0) {
                com.google.android.gms.ads.internal.j.C.k.getClass();
                fiA.o("p_imp_l", String.valueOf(System.currentTimeMillis() - this.h));
            }
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.nd)).booleanValue() && q()) {
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                fiA.o("foreground", true != com.google.android.gms.ads.internal.util.F.f(this.a) ? "1" : "0");
                fiA.o("fg_show", true == this.k.get() ? "1" : "0");
            }
            b(fiA);
        }
    }

    public final Fi a(String str) {
        C1849aq c1849aq = this.d;
        androidx.work.impl.model.n nVar = c1849aq.b;
        Fi fiA = this.c.a();
        fiA.o("gqi", ((Xp) nVar.b).b);
        Vp vp = this.e;
        fiA.p(vp);
        fiA.o("action", str);
        fiA.o("ad_format", this.g.toUpperCase(Locale.ROOT));
        List list = vp.t;
        if (!list.isEmpty()) {
            fiA.o("ancn", (String) list.get(0));
        }
        if (vp.b()) {
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            fiA.o("device_connectivity", true != jVar.h.a(this.a) ? "offline" : "online");
            jVar.k.getClass();
            fiA.o("event_timestamp", String.valueOf(System.currentTimeMillis()));
            fiA.o("offline_ad", "1");
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.R6)).booleanValue()) {
            S4 s4 = c1849aq.a;
            boolean z = AbstractC3429b3.g((C2023eq) s4.b) != 1;
            fiA.o("scar", String.valueOf(z));
            if (z) {
                zzm zzmVar = ((C2023eq) s4.b).d;
                fiA.o("ragent", zzmVar.p);
                fiA.o("rtype", AbstractC3429b3.d(AbstractC3429b3.e(zzmVar)));
            }
        }
        return fiA;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0053  */
    @Override // com.google.android.gms.internal.ads.InterfaceC1884bh
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a0(com.google.android.gms.ads.internal.client.zze r5) {
        /*
            r4 = this;
            boolean r0 = r4.j
            if (r0 != 0) goto L5
            return
        L5:
            java.lang.String r0 = "ifts"
            com.google.android.gms.internal.ads.Fi r0 = r4.a(r0)
            java.lang.String r1 = "reason"
            java.lang.String r2 = "adapter"
            r0.o(r1, r2)
            int r1 = r5.a
            java.lang.String r2 = r5.c
            java.lang.String r3 = "com.google.android.gms.ads"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L2e
            com.google.android.gms.ads.internal.client.zze r2 = r5.d
            if (r2 == 0) goto L2e
            java.lang.String r2 = r2.c
            boolean r2 = r2.equals(r3)
            if (r2 != 0) goto L2e
            com.google.android.gms.ads.internal.client.zze r5 = r5.d
            int r1 = r5.a
        L2e:
            java.lang.String r5 = r5.b
            if (r1 < 0) goto L3b
            java.lang.String r2 = "arec"
            java.lang.String r1 = java.lang.String.valueOf(r1)
            r0.o(r2, r1)
        L3b:
            com.google.android.gms.internal.ads.kq r1 = r4.b
            java.util.regex.Pattern r1 = r1.a
            if (r1 == 0) goto L53
            if (r5 != 0) goto L44
            goto L53
        L44:
            java.util.regex.Matcher r5 = r1.matcher(r5)
            boolean r1 = r5.find()
            if (r1 == 0) goto L53
            java.lang.String r5 = r5.group()
            goto L54
        L53:
            r5 = 0
        L54:
            if (r5 == 0) goto L5b
            java.lang.String r1 = "areec"
            r0.o(r1, r5)
        L5b:
            r0.x()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ak.a0(com.google.android.gms.ads.internal.client.zze):void");
    }

    public final void b(Fi fi) {
        if (!this.e.b()) {
            fi.x();
            return;
        }
        Kk kk = ((Hk) fi.c).a;
        String strA = kk.f.a((ConcurrentHashMap) fi.b);
        com.google.android.gms.ads.internal.j.C.k.getClass();
        com.android.volley.toolbox.d dVar = new com.android.volley.toolbox.d(2, System.currentTimeMillis(), ((Xp) this.d.b.b).b, strA);
        C2107gm c2107gm = this.f;
        c2107gm.getClass();
        c2107gm.d(new C1732Mb(26, c2107gm, dVar));
    }

    @Override // com.google.android.gms.internal.ads.Dh
    public final void c() {
        if (r()) {
            this.l.set(true);
            com.google.android.gms.ads.internal.j.C.k.getClass();
            this.h = System.currentTimeMillis();
            Fi fiA = a("presentation");
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.nd)).booleanValue() && q()) {
                AtomicBoolean atomicBoolean = this.k;
                atomicBoolean.set(!com.google.android.gms.ads.internal.util.F.f(this.a));
                fiA.o("foreground", true != atomicBoolean.get() ? "0" : "1");
            }
            fiA.x();
        }
    }

    @Override // com.google.android.gms.internal.ads.Ph
    public final void d() {
        if (r()) {
            Fi fiA = a("adapter_impression");
            if (this.l.get()) {
                fiA.o("po", "1");
                com.google.android.gms.ads.internal.j.C.k.getClass();
                fiA.o("pil", String.valueOf(System.currentTimeMillis() - this.h));
            } else {
                fiA.o("po", "0");
            }
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.nd)).booleanValue() && q()) {
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                fiA.o("foreground", true != com.google.android.gms.ads.internal.util.F.f(this.a) ? "1" : "0");
                fiA.o("fg_show", true == this.k.get() ? "1" : "0");
            }
            fiA.x();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1884bh
    public final void j() {
        if (this.j) {
            Fi fiA = a("ifts");
            fiA.o("reason", "blocked");
            fiA.x();
        }
    }

    @Override // com.google.android.gms.internal.ads.Ph
    public final void o() {
        if (r()) {
            a("adapter_shown").x();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        if (this.e.b()) {
            b(a("click"));
        }
    }

    public final boolean q() {
        int i = this.e.b;
        return i == 2 || i == 5 || i == 6 || i == 7;
    }

    public final boolean r() {
        String strG;
        if (this.i == null) {
            synchronized (this) {
                if (this.i == null) {
                    String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.w1);
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    try {
                        strG = com.google.android.gms.ads.internal.util.F.G(this.a);
                    } catch (RemoteException unused) {
                        strG = null;
                    }
                    boolean zMatches = false;
                    if (str != null && strG != null) {
                        try {
                            zMatches = Pattern.matches(str, strG);
                        } catch (RuntimeException e) {
                            com.google.android.gms.ads.internal.j.C.h.h("CsiActionsListener.isPatternMatched", e);
                        }
                    }
                    this.i = Boolean.valueOf(zMatches);
                }
            }
        }
        return this.i.booleanValue();
    }
}
