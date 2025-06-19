package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.webkit.WebView;
import android.widget.ImageView;
import androidx.collection.C0208f;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Ui extends AbstractC2359mg {
    public static final Bu H;
    public final P4 A;
    public final VersionInfoParcel B;
    public final Context C;
    public final Wi D;
    public final Mn E;
    public final HashMap F;
    public final ArrayList G;
    public final Executor j;
    public final Yi k;
    public final InterfaceC1886bj l;
    public final C2191ij m;
    public final C1842aj n;
    public final C1929cj o;
    public final InterfaceC2907zC p;
    public final InterfaceC2907zC q;
    public final InterfaceC2907zC r;
    public final InterfaceC2907zC s;
    public final InterfaceC2907zC t;
    public AbstractBinderC2814x5 u;
    public boolean v;
    public boolean w;
    public boolean x;
    public boolean y;
    public final C1727Lc z;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        Object[] objArr = {"3010", "3008", "1005", "1009", "2011", "2007"};
        AbstractC2457os.q(6, objArr);
        H = AbstractC2330lu.m(6, objArr);
    }

    public Ui(com.google.android.datatransport.cct.internal.s sVar, Executor executor, Yi yi, InterfaceC1886bj interfaceC1886bj, C2191ij c2191ij, C1842aj c1842aj, C1929cj c1929cj, InterfaceC2907zC interfaceC2907zC, InterfaceC2907zC interfaceC2907zC2, InterfaceC2907zC interfaceC2907zC3, InterfaceC2907zC interfaceC2907zC4, InterfaceC2907zC interfaceC2907zC5, C1727Lc c1727Lc, P4 p4, VersionInfoParcel versionInfoParcel, Context context, Wi wi, Mn mn) {
        super(sVar);
        this.j = executor;
        this.k = yi;
        this.l = interfaceC1886bj;
        this.m = c2191ij;
        this.n = c1842aj;
        this.o = c1929cj;
        this.p = interfaceC2907zC;
        this.q = interfaceC2907zC2;
        this.r = interfaceC2907zC3;
        this.s = interfaceC2907zC4;
        this.t = interfaceC2907zC5;
        this.z = c1727Lc;
        this.A = p4;
        this.B = versionInfoParcel;
        this.C = context;
        this.D = wi;
        this.E = mn;
        this.F = new HashMap();
        this.G = new ArrayList();
    }

    public static boolean h(View view) {
        C2601s7 c2601s7 = AbstractC2773w7.Da;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            return view.isShown() && view.getGlobalVisibleRect(new Rect(), new Point());
        }
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        long jK = com.google.android.gms.ads.internal.util.F.K(view);
        if (view.isShown() && view.getGlobalVisibleRect(new Rect(), new Point())) {
            return jK >= ((long) ((Integer) rVar.c.a(AbstractC2773w7.Ea)).intValue());
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2359mg
    public final void a() {
        Si si = new Si(this, 0);
        Executor executor = this.j;
        executor.execute(si);
        if (this.k.g() != 7) {
            InterfaceC1886bj interfaceC1886bj = this.l;
            Objects.requireNonNull(interfaceC1886bj);
            executor.execute(new RunnableC1989e(interfaceC1886bj, 29));
        }
        super.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x004a A[Catch: all -> 0x000a, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0005, B:10:0x000d, B:12:0x001f, B:14:0x0025, B:15:0x002f, B:17:0x0035, B:21:0x004a, B:24:0x005e, B:25:0x0066, B:27:0x006c, B:29:0x0080, B:31:0x0086, B:36:0x008d), top: B:41:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x008d A[Catch: all -> 0x000a, TRY_ENTER, TRY_LEAVE, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0005, B:10:0x000d, B:12:0x001f, B:14:0x0025, B:15:0x002f, B:17:0x0035, B:21:0x004a, B:24:0x005e, B:25:0x0066, B:27:0x006c, B:29:0x0080, B:31:0x0086, B:36:0x008d), top: B:41:0x0001 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void b(android.view.View r4, java.util.Map r5, java.util.Map r6, boolean r7) {
        /*
            r3 = this;
            monitor-enter(r3)
            boolean r0 = r3.w     // Catch: java.lang.Throwable -> La
            if (r0 == 0) goto Ld
            r3.l(r4, r5, r6)     // Catch: java.lang.Throwable -> La
            monitor-exit(r3)
            return
        La:
            r4 = move-exception
            goto L95
        Ld:
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.N1     // Catch: java.lang.Throwable -> La
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> La
            com.google.android.gms.internal.ads.u7 r1 = r1.c     // Catch: java.lang.Throwable -> La
            java.lang.Object r0 = r1.a(r0)     // Catch: java.lang.Throwable -> La
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> La
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> La
            if (r0 == 0) goto L48
            com.google.android.gms.internal.ads.Vp r0 = r3.b     // Catch: java.lang.Throwable -> La
            boolean r0 = r0.k0     // Catch: java.lang.Throwable -> La
            if (r0 == 0) goto L48
            java.util.HashMap r0 = r3.F     // Catch: java.lang.Throwable -> La
            java.util.Set r1 = r0.keySet()     // Catch: java.lang.Throwable -> La
            java.util.Iterator r1 = r1.iterator()     // Catch: java.lang.Throwable -> La
        L2f:
            boolean r2 = r1.hasNext()     // Catch: java.lang.Throwable -> La
            if (r2 == 0) goto L48
            java.lang.Object r2 = r1.next()     // Catch: java.lang.Throwable -> La
            java.lang.String r2 = (java.lang.String) r2     // Catch: java.lang.Throwable -> La
            java.lang.Object r2 = r0.get(r2)     // Catch: java.lang.Throwable -> La
            java.lang.Boolean r2 = (java.lang.Boolean) r2     // Catch: java.lang.Throwable -> La
            boolean r2 = r2.booleanValue()     // Catch: java.lang.Throwable -> La
            if (r2 != 0) goto L2f
            goto L8b
        L48:
            if (r7 != 0) goto L8d
            com.google.android.gms.internal.ads.s7 r7 = com.google.android.gms.internal.ads.AbstractC2773w7.Y3     // Catch: java.lang.Throwable -> La
            com.google.android.gms.ads.internal.client.r r0 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> La
            com.google.android.gms.internal.ads.u7 r0 = r0.c     // Catch: java.lang.Throwable -> La
            java.lang.Object r7 = r0.a(r7)     // Catch: java.lang.Throwable -> La
            java.lang.Boolean r7 = (java.lang.Boolean) r7     // Catch: java.lang.Throwable -> La
            boolean r7 = r7.booleanValue()     // Catch: java.lang.Throwable -> La
            if (r7 == 0) goto L8b
            if (r5 == 0) goto L8b
            java.util.Set r7 = r5.entrySet()     // Catch: java.lang.Throwable -> La
            java.util.Iterator r7 = r7.iterator()     // Catch: java.lang.Throwable -> La
        L66:
            boolean r0 = r7.hasNext()     // Catch: java.lang.Throwable -> La
            if (r0 == 0) goto L8b
            java.lang.Object r0 = r7.next()     // Catch: java.lang.Throwable -> La
            java.util.Map$Entry r0 = (java.util.Map.Entry) r0     // Catch: java.lang.Throwable -> La
            java.lang.Object r0 = r0.getValue()     // Catch: java.lang.Throwable -> La
            java.lang.ref.WeakReference r0 = (java.lang.ref.WeakReference) r0     // Catch: java.lang.Throwable -> La
            java.lang.Object r0 = r0.get()     // Catch: java.lang.Throwable -> La
            android.view.View r0 = (android.view.View) r0     // Catch: java.lang.Throwable -> La
            if (r0 == 0) goto L66
            boolean r0 = h(r0)     // Catch: java.lang.Throwable -> La
            if (r0 == 0) goto L66
            r3.m(r4, r5, r6)     // Catch: java.lang.Throwable -> La
            monitor-exit(r3)
            return
        L8b:
            monitor-exit(r3)
            return
        L8d:
            r3.m(r4, r5, r6)     // Catch: java.lang.Throwable -> La
            r3.l(r4, r5, r6)     // Catch: java.lang.Throwable -> La
            monitor-exit(r3)
            return
        L95:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> La
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ui.b(android.view.View, java.util.Map, java.util.Map, boolean):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x003b A[Catch: all -> 0x0057, TryCatch #1 {, blocks: (B:3:0x0001, B:5:0x0007, B:7:0x000b, B:10:0x0012, B:12:0x001a, B:14:0x0026, B:15:0x0029, B:17:0x003b, B:20:0x0044, B:22:0x004a), top: B:33:0x0001, inners: #0 }] */
    /* JADX WARN: Type inference failed for: r1v0, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void c(android.view.View r8, android.view.View r9, java.util.Map r10, java.util.Map r11, boolean r12) {
        /*
            r7 = this;
            monitor-enter(r7)
            com.google.android.gms.internal.ads.ij r0 = r7.m     // Catch: java.lang.Throwable -> L57
            com.google.android.gms.internal.ads.x5 r1 = r7.u     // Catch: java.lang.Throwable -> L57
            if (r1 == 0) goto L29
            com.google.android.gms.internal.ads.qj r2 = r0.e     // Catch: java.lang.Throwable -> L57
            if (r2 == 0) goto L29
            android.widget.FrameLayout r3 = r1.g()     // Catch: java.lang.Throwable -> L57
            if (r3 != 0) goto L12
            goto L29
        L12:
            com.google.android.gms.internal.ads.aj r0 = r0.c     // Catch: java.lang.Throwable -> L57
            boolean r0 = r0.f()     // Catch: java.lang.Throwable -> L57
            if (r0 == 0) goto L29
            android.widget.FrameLayout r0 = r1.g()     // Catch: com.google.android.gms.internal.ads.zzcfn -> L26 java.lang.Throwable -> L57
            android.view.View r1 = r2.a()     // Catch: com.google.android.gms.internal.ads.zzcfn -> L26 java.lang.Throwable -> L57
            r0.addView(r1)     // Catch: com.google.android.gms.internal.ads.zzcfn -> L26 java.lang.Throwable -> L57
            goto L29
        L26:
            com.google.android.gms.ads.internal.util.A.m()     // Catch: java.lang.Throwable -> L57
        L29:
            android.widget.ImageView$ScaleType r6 = r7.j()     // Catch: java.lang.Throwable -> L57
            com.google.android.gms.internal.ads.bj r0 = r7.l     // Catch: java.lang.Throwable -> L57
            r1 = r8
            r2 = r9
            r3 = r10
            r4 = r11
            r5 = r12
            r0.m(r1, r2, r3, r4, r5, r6)     // Catch: java.lang.Throwable -> L57
            boolean r8 = r7.y     // Catch: java.lang.Throwable -> L57
            if (r8 == 0) goto L5a
            com.google.android.gms.internal.ads.Yi r8 = r7.k     // Catch: java.lang.Throwable -> L57
            com.google.android.gms.internal.ads.qe r9 = r8.m()     // Catch: java.lang.Throwable -> L57
            if (r9 != 0) goto L44
            goto L5a
        L44:
            com.google.android.gms.internal.ads.qe r8 = r8.m()     // Catch: java.lang.Throwable -> L57
            if (r8 == 0) goto L5a
            androidx.collection.f r9 = new androidx.collection.f     // Catch: java.lang.Throwable -> L57
            r10 = 0
            r9.<init>(r10)     // Catch: java.lang.Throwable -> L57
            java.lang.String r10 = "onSdkAdUserInteractionClick"
            r8.j(r10, r9)     // Catch: java.lang.Throwable -> L57
            monitor-exit(r7)
            return
        L57:
            r0 = move-exception
            r8 = r0
            goto L5c
        L5a:
            monitor-exit(r7)
            return
        L5c:
            monitor-exit(r7)     // Catch: java.lang.Throwable -> L57
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ui.c(android.view.View, android.view.View, java.util.Map, java.util.Map, boolean):void");
    }

    public final synchronized void d(int i, View view) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.zb)).booleanValue()) {
            AbstractBinderC2814x5 abstractBinderC2814x5 = this.u;
            if (abstractBinderC2814x5 == null) {
                com.google.android.gms.ads.internal.util.client.i.d("Ad should be associated with an ad view before calling performClickForCustomGesture()");
            } else {
                this.j.execute(new androidx.work.impl.utils.j(this, view, abstractBinderC2814x5 instanceof ViewTreeObserverOnGlobalLayoutListenerC2060fj, i));
            }
        }
    }

    public final void e(View view) {
        C2313ld c2313ld;
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.r5)).booleanValue();
        Yi yi = this.k;
        if (!zBooleanValue || yi.g() == 3) {
            n(view, yi.o());
            return;
        }
        synchronized (yi) {
            c2313ld = yi.n;
        }
        if (c2313ld == null) {
            return;
        }
        C1732Mb c1732Mb = new C1732Mb(this, false, view, 19);
        c2313ld.a(new Qv(0, c2313ld, c1732Mb), this.j);
    }

    public final synchronized void f(InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L1)).booleanValue()) {
            com.google.android.gms.ads.internal.util.F.l.post(new Qi(this, interfaceViewOnClickListenerC2705uj, 0));
        } else {
            o(interfaceViewOnClickListenerC2705uj);
        }
    }

    public final synchronized void g(InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L1)).booleanValue()) {
            com.google.android.gms.ads.internal.util.F.l.post(new Qi(this, interfaceViewOnClickListenerC2705uj, 1));
        } else {
            q(interfaceViewOnClickListenerC2705uj);
        }
    }

    public final synchronized boolean i(Bundle bundle) {
        if (this.w) {
            return true;
        }
        boolean zR = this.l.r(bundle);
        this.w = zR;
        return zR;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    public final synchronized ImageView.ScaleType j() {
        ?? r0 = this.u;
        if (r0 == 0) {
            com.google.android.gms.ads.internal.util.client.i.d("Ad should be associated with an ad view before calling getMediaviewScaleType()");
            return null;
        }
        com.google.android.gms.dynamic.a aVarI = r0.i();
        if (aVarI != null) {
            return (ImageView.ScaleType) com.google.android.gms.dynamic.b.I3(aVarI);
        }
        return C2191ij.k;
    }

    public final void k() {
        com.google.common.util.concurrent.e eVar;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.r5)).booleanValue()) {
            s("Google", true);
            return;
        }
        Yi yi = this.k;
        synchronized (yi) {
            eVar = yi.m;
        }
        if (eVar == null) {
            return;
        }
        Ts ts = new Ts(this, 19);
        eVar.a(new Qv(0, eVar, ts), this.j);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0031 A[Catch: all -> 0x0075, TryCatch #0 {, blocks: (B:3:0x0001, B:6:0x0007, B:14:0x0028, B:21:0x0031, B:23:0x0044, B:25:0x0054, B:27:0x005e, B:29:0x0068, B:34:0x0078, B:36:0x0088, B:38:0x008e, B:41:0x009b, B:43:0x00b0, B:45:0x00cd, B:47:0x00e9, B:18:0x002d, B:53:0x00f9, B:9:0x000b, B:11:0x0012, B:13:0x0022), top: B:56:0x0001, inners: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void l(android.view.View r9, java.util.Map r10, java.util.Map r11) {
        /*
            Method dump skipped, instructions count: 252
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ui.l(android.view.View, java.util.Map, java.util.Map):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    public final synchronized void m(View view, Map map, Map map2) {
        this.m.a(this.u);
        this.l.h(view, map, map2, j());
        this.w = true;
    }

    public final void n(View view, C2665tm c2665tm) {
        InterfaceC2529qe interfaceC2529qeL = this.k.l();
        if (!this.n.c() || c2665tm == null || interfaceC2529qeL == null || view == null) {
            return;
        }
        C2147hi c2147hi = com.google.android.gms.ads.internal.j.C.x;
        Hr hr = c2665tm.a;
        c2147hi.getClass();
        C2147hi.j(hr, view);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    public final synchronized void o(InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj) {
        Iterator<String> itKeys;
        View view;
        N4 n4;
        try {
            if (!this.v) {
                this.u = (AbstractBinderC2814x5) interfaceViewOnClickListenerC2705uj;
                C2191ij c2191ij = this.m;
                c2191ij.g.execute(new Qv(c2191ij, interfaceViewOnClickListenerC2705uj));
                this.l.b(interfaceViewOnClickListenerC2705uj.f(), interfaceViewOnClickListenerC2705uj.l(), interfaceViewOnClickListenerC2705uj.m(), interfaceViewOnClickListenerC2705uj, interfaceViewOnClickListenerC2705uj);
                C2601s7 c2601s7 = AbstractC2773w7.K2;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && (n4 = this.A.b) != null) {
                    n4.a(interfaceViewOnClickListenerC2705uj.f());
                }
                if (((Boolean) rVar.c.a(AbstractC2773w7.N1)).booleanValue()) {
                    Vp vp = this.b;
                    if (vp.k0 && (itKeys = vp.j0.keys()) != null) {
                        while (itKeys.hasNext()) {
                            String next = itKeys.next();
                            ?? r2 = this.u;
                            WeakReference weakReference = r2 == 0 ? null : (WeakReference) r2.k().get(next);
                            this.F.put(next, Boolean.FALSE);
                            if (weakReference != null && (view = (View) weakReference.get()) != null) {
                                F5 f5 = new F5(this.C, view);
                                this.G.add(f5);
                                f5.l.add(new Ti(this, next));
                                f5.c(3);
                            }
                        }
                    }
                }
                if (interfaceViewOnClickListenerC2705uj.zzi() != null) {
                    F5 f5Zzi = interfaceViewOnClickListenerC2705uj.zzi();
                    f5Zzi.l.add(this.z);
                    f5Zzi.c(3);
                }
            }
        } finally {
        }
    }

    public final void q(InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj) {
        View viewF = interfaceViewOnClickListenerC2705uj.f();
        interfaceViewOnClickListenerC2705uj.k();
        this.l.f(viewF);
        if (interfaceViewOnClickListenerC2705uj.g() != null) {
            interfaceViewOnClickListenerC2705uj.g().setClickable(false);
            interfaceViewOnClickListenerC2705uj.g().removeAllViews();
        }
        if (interfaceViewOnClickListenerC2705uj.zzi() != null) {
            F5 f5Zzi = interfaceViewOnClickListenerC2705uj.zzi();
            f5Zzi.l.remove(this.z);
        }
        this.u = null;
    }

    public final synchronized void r() {
        this.v = true;
        this.j.execute(new Si(this, 1));
        C2403nh c2403nh = this.c;
        c2403nh.getClass();
        c2403nh.j1(new C2360mh(null));
    }

    public final C2665tm s(String str, boolean z) {
        boolean z2;
        boolean z3;
        String str2;
        int i;
        int i2;
        com.google.android.gms.ads.internal.j jVar;
        C2665tm c2665tm;
        Object objD;
        C1842aj c1842aj = this.n;
        if (c1842aj.c() && !TextUtils.isEmpty(str)) {
            Yi yi = this.k;
            InterfaceC2529qe interfaceC2529qeL = yi.l();
            InterfaceC2529qe interfaceC2529qeM = yi.m();
            if (interfaceC2529qeL == null && interfaceC2529qeM == null) {
                com.google.android.gms.ads.internal.util.client.i.h("Omid display and video webview are null. Skipping initialization.");
                return null;
            }
            c1842aj.a();
            int iK = c1842aj.a().K();
            int i3 = iK - 1;
            if (i3 != 0) {
                if (i3 != 1) {
                    com.google.android.gms.ads.internal.util.client.i.h("Unknown omid media type: " + (iK != 1 ? iK != 2 ? "UNKNOWN" : "DISPLAY" : "VIDEO") + ". Not initializing Omid.");
                    return null;
                }
                if (interfaceC2529qeL == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Omid media type was display but there was no display webview.");
                    return null;
                }
                z3 = false;
                z2 = true;
            } else if (interfaceC2529qeM != null) {
                z2 = false;
                z3 = true;
            } else {
                com.google.android.gms.ads.internal.util.client.i.h("Omid media type was video but there was no video webview.");
            }
            if (z2) {
                str2 = null;
            } else {
                str2 = "javascript";
                interfaceC2529qeL = interfaceC2529qeM;
            }
            if (interfaceC2529qeL == null) {
                com.google.android.gms.ads.internal.util.client.i.h("Webview is null in InternalNativeAd");
                return null;
            }
            Context context = this.C;
            com.google.android.gms.ads.internal.j jVar2 = com.google.android.gms.ads.internal.j.C;
            jVar2.x.getClass();
            if (!C2147hi.l(context)) {
                com.google.android.gms.ads.internal.util.client.i.h("Failed to initialize omid in InternalNativeAd");
                return null;
            }
            VersionInfoParcel versionInfoParcel = this.B;
            String str3 = versionInfoParcel.b + "." + versionInfoParcel.c;
            if (z3) {
                i2 = 3;
                i = 2;
            } else {
                i = yi.g() == 3 ? 4 : 3;
                i2 = 2;
            }
            C2147hi c2147hi = jVar2.x;
            WebView webViewN = interfaceC2529qeL.n();
            String str4 = this.b.l0;
            c2147hi.getClass();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue() && AbstractC1972di.M.b) {
                jVar = jVar2;
                try {
                    objD = new C2537qm(str, str3, str2, i2, webViewN, str4, i).d();
                } catch (RuntimeException e) {
                    com.google.android.gms.ads.internal.j.C.h.g("omid exception", e);
                    objD = null;
                }
                c2665tm = (C2665tm) objD;
            } else {
                jVar = jVar2;
                c2665tm = null;
            }
            if (c2665tm == null) {
                com.google.android.gms.ads.internal.util.client.i.h("Failed to create omid session in InternalNativeAd");
                return null;
            }
            synchronized (yi) {
                yi.l = c2665tm;
            }
            interfaceC2529qeL.B0(c2665tm);
            if (z3) {
                Hr hr = c2665tm.a;
                if (interfaceC2529qeM != null) {
                    View viewN = interfaceC2529qeM.N();
                    jVar.x.getClass();
                    C2147hi.j(hr, viewN);
                }
                this.y = true;
            }
            if (z) {
                C2147hi c2147hi2 = jVar.x;
                Hr hr2 = c2665tm.a;
                c2147hi2.getClass();
                C2147hi.k(hr2);
                interfaceC2529qeL.j("onSdkLoaded", new C0208f(0));
            }
            return c2665tm;
        }
        return null;
    }
}
