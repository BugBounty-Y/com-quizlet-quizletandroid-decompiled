package com.google.android.gms.internal.ads;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.net.Uri;
import android.os.RemoteException;
import android.view.View;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.zze;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.Df, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1682Df implements Xg, InterfaceC2617sh, InterfaceC2189ih, InterfaceC1582a, InterfaceC2102gh, InterfaceC2275ki, Dh {
    public final Context a;
    public final Xv b;
    public final Executor c;
    public final ScheduledExecutorService d;
    public final C1849aq e;
    public final Vp f;
    public final C2542qr g;
    public final C2155hq h;
    public final P4 i;
    public final J7 j;
    public final WeakReference k;
    public final WeakReference l;
    public final C2326lq m;
    public final Ah n;
    public boolean o;
    public final AtomicBoolean p = new AtomicBoolean();

    public C1682Df(Context context, Xv xv, Executor executor, ScheduledExecutorService scheduledExecutorService, C1849aq c1849aq, Vp vp, C2542qr c2542qr, C2155hq c2155hq, View view, InterfaceC2529qe interfaceC2529qe, P4 p4, J7 j7, C2326lq c2326lq, Ah ah) {
        this.a = context;
        this.b = xv;
        this.c = executor;
        this.d = scheduledExecutorService;
        this.e = c1849aq;
        this.f = vp;
        this.g = c2542qr;
        this.h = c2155hq;
        this.i = p4;
        this.k = new WeakReference(view);
        this.l = new WeakReference(interfaceC2529qe);
        this.j = j7;
        this.m = c2326lq;
        this.n = ah;
    }

    public final void A(int i, int i2) {
        View view;
        if (i <= 0 || !((view = (View) this.k.get()) == null || view.getHeight() == 0 || view.getWidth() == 0)) {
            o();
        } else {
            this.d.schedule(new RunnableC1676Cf(this, i, i2, 0), i2, TimeUnit.MILLISECONDS);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        if (this.p.compareAndSet(false, true)) {
            C2601s7 c2601s7 = AbstractC2773w7.O3;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            int iIntValue = ((Integer) rVar.c.a(c2601s7)).intValue();
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (iIntValue > 0) {
                A(iIntValue, ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.P3)).intValue());
            } else if (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.N3)).booleanValue()) {
                o();
            } else {
                this.c.execute(new RunnableC1670Bf(this, 0));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.util.AbstractCollection, java.util.List] */
    @Override // com.google.android.gms.internal.ads.Dh
    public final void c() {
        Vp vp = this.f;
        if (vp.e == 4) {
            this.h.a(this.g.b(this.e, vp, vp.A0), null);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [java.util.AbstractCollection, java.util.List] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2275ki
    public final void d() {
        Vp vp = this.f;
        this.h.a(this.g.b(this.e, vp, vp.u0), null);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
        Vp vp = this.f;
        this.h.a(this.g.b(this.e, vp, vp.g), null);
    }

    public final List j() {
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.sb)).booleanValue();
        Vp vp = this.f;
        if (zBooleanValue) {
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            Context context = this.a;
            if (com.google.android.gms.ads.internal.util.F.c(context)) {
                Object systemService = context.getSystemService("display");
                Integer numValueOf = systemService instanceof DisplayManager ? Integer.valueOf(((DisplayManager) systemService).getDisplays().length) : null;
                if (numValueOf != null) {
                    int iMin = Math.min(numValueOf.intValue(), 20);
                    ArrayList arrayList = new ArrayList();
                    Iterator it2 = vp.d.iterator();
                    while (it2.hasNext()) {
                        arrayList.add(Uri.parse((String) it2.next()).buildUpon().appendQueryParameter("dspct", Integer.toString(iMin)).toString());
                    }
                    return arrayList;
                }
            }
        }
        return vp.d;
    }

    public final void o() {
        int i;
        Vp vp = this.f;
        List list = vp.d;
        if (list == null || list.isEmpty()) {
            return;
        }
        C2601s7 c2601s7 = AbstractC2773w7.F3;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        String strI = null;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            strI = this.i.b.i(this.a, (View) this.k.get(), null);
        }
        String str = strI;
        C2601s7 c2601s72 = AbstractC2773w7.w0;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if ((((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue() && ((Xp) this.e.b.b).h) || !((Boolean) V7.h.o()).booleanValue()) {
            this.h.a(this.g.c(this.e, vp, false, str, null, j()), this.n);
            return;
        }
        if (((Boolean) V7.g.o()).booleanValue() && ((i = vp.b) == 1 || i == 2 || i == 5)) {
        }
        Nv nv = (Nv) AbstractC2025es.O(Nv.t(Tv.b), ((Long) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Z0)).longValue(), TimeUnit.MILLISECONDS, this.d);
        nv.a(new Qv(0, nv, new C1732Mb(this, false, str, 15)), this.b);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.w0)).booleanValue();
        C1849aq c1849aq = this.e;
        if ((zBooleanValue && ((Xp) c1849aq.b.b).h) || !((Boolean) V7.d.o()).booleanValue()) {
            Vp vp = this.f;
            this.h.b(true == com.google.android.gms.ads.internal.j.C.h.a(this.a) ? 2 : 1, this.g.b(c1849aq, vp, vp.c));
        } else {
            J7 j7 = this.j;
            j7.getClass();
            C2072fv c2072fvX = AbstractC2025es.x(Nv.t((Nv) AbstractC2025es.O(Nv.t(Tv.b), ((Long) V7.c.o()).longValue(), TimeUnit.MILLISECONDS, j7.c)), Throwable.class, new C2853y1(4), AbstractC2270kd.g);
            c2072fvX.a(new Qv(0, c2072fvX, new C2881yn(this, 11)), this.b);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final void r(zze zzeVar) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.y1)).booleanValue()) {
            int i = zzeVar.a;
            ArrayList arrayList = new ArrayList();
            Vp vp = this.f;
            Iterator it2 = vp.o.iterator();
            while (it2.hasNext()) {
                arrayList.add(C2542qr.a((String) it2.next(), "@gw_mpe@", "2." + i));
            }
            this.h.a(this.g.b(this.e, vp, arrayList), null);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final synchronized void s() {
        C2326lq c2326lq;
        long j;
        try {
            if (this.o) {
                ArrayList arrayList = new ArrayList(j());
                Vp vp = this.f;
                arrayList.addAll(vp.f);
                this.h.a(this.g.c(this.e, vp, true, null, null, arrayList), null);
            } else {
                C2155hq c2155hq = this.h;
                C2542qr c2542qr = this.g;
                C1849aq c1849aq = this.e;
                Vp vp2 = this.f;
                c2155hq.a(c2542qr.b(c1849aq, vp2, vp2.m), null);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K3)).booleanValue() && (c2326lq = this.m) != null) {
                    List list = ((Vp) c2326lq.c).m;
                    String strB = ((C2195in) c2326lq.d).b();
                    ArrayList arrayList2 = new ArrayList();
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        arrayList2.add(C2542qr.a((String) it2.next(), "@gw_adnetstatus@", strB));
                    }
                    C2195in c2195in = (C2195in) c2326lq.d;
                    synchronized (c2195in) {
                        j = c2195in.h;
                    }
                    ArrayList arrayList3 = new ArrayList();
                    Iterator it3 = arrayList2.iterator();
                    while (it3.hasNext()) {
                        arrayList3.add(C2542qr.a((String) it3.next(), "@gw_ttr@", Long.toString(j, 10)));
                    }
                    c2155hq.a(c2542qr.b((C1849aq) c2326lq.b, (Vp) c2326lq.c, arrayList3), null);
                }
                c2155hq.a(c2542qr.b(c1849aq, vp2, vp2.f), null);
            }
            this.o = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
        C1893bq c1893bq;
        Vp vp = this.f;
        List list = vp.h;
        C2542qr c2542qr = this.g;
        c2542qr.getClass();
        ArrayList arrayList = new ArrayList();
        long jCurrentTimeMillis = c2542qr.h.currentTimeMillis();
        try {
            String str3 = binderC1966dc.a;
            String string = Integer.toString(binderC1966dc.b);
            boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G3)).booleanValue();
            AbstractC2672tt c2801wt = C2458ot.a;
            if (zBooleanValue) {
                C1936cq c1936cq = c2542qr.g;
                if (c1936cq != null && (c1893bq = c1936cq.a) != null) {
                    c2801wt = new C2801wt(c1893bq);
                }
            } else {
                C1893bq c1893bq2 = c2542qr.f;
                if (c1893bq2 != null) {
                    c2801wt = new C2801wt(c1893bq2);
                }
            }
            String str4 = (String) c2801wt.a(new C2853y1(17)).b();
            String str5 = (String) c2801wt.a(new C2853y1(18)).b();
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                arrayList.add(AbstractC1795We.u(C2542qr.a(C2542qr.a(C2542qr.a(C2542qr.a(C2542qr.a(C2542qr.a((String) it2.next(), "@gw_rwd_userid@", Uri.encode(str4)), "@gw_rwd_custom_data@", Uri.encode(str5)), "@gw_tmstmp@", Long.toString(jCurrentTimeMillis)), "@gw_rwd_itm@", Uri.encode(str3)), "@gw_rwd_amt@", string), "@gw_sdkver@", c2542qr.b), c2542qr.e, vp.W, vp.w0));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to determine award type and amount.", e);
        }
        this.h.a(arrayList, null);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
        Vp vp = this.f;
        this.h.a(this.g.b(this.e, vp, vp.i), null);
    }
}
