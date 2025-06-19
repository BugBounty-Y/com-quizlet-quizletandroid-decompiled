package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.view.KeyEvent;
import android.view.ViewGroup;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toolbar;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.overlay.zzc;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* renamed from: com.google.android.gms.internal.ads.Be, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1669Be extends WebViewClient implements InterfaceC1582a, InterfaceC2447oi {
    public static final /* synthetic */ int H = 0;
    public boolean A;
    public boolean B;
    public int C;
    public boolean D;
    public final BinderC2408nm F;
    public ViewOnAttachStateChangeListenerC2571re G;
    public final C2743ve a;
    public final C2429o6 b;
    public InterfaceC1582a e;
    public com.google.android.gms.ads.internal.overlay.j f;
    public InterfaceC1681De g;
    public InterfaceC1687Ee h;
    public InterfaceC1999e9 i;
    public InterfaceC2043f9 j;
    public InterfaceC2447oi k;
    public boolean l;
    public boolean m;
    public boolean q;
    public boolean r;
    public boolean s;
    public boolean t;
    public com.google.android.gms.ads.internal.overlay.c u;
    public C2526qb v;
    public com.google.android.gms.ads.internal.a w;
    public InterfaceC1679Dc y;
    public Hk z;
    public final HashMap c = new HashMap();
    public final Object d = new Object();
    public int n = 0;
    public String o = "";
    public String p = "";
    public C2397nb x = null;
    public final HashSet E = new HashSet(Arrays.asList(((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H5)).split(",")));

    public C1669Be(C2743ve c2743ve, C2429o6 c2429o6, boolean z, C2526qb c2526qb, BinderC2408nm binderC2408nm) {
        this.b = c2429o6;
        this.a = c2743ve;
        this.q = z;
        this.v = c2526qb;
        this.F = binderC2408nm;
    }

    public static final boolean E(C2743ve c2743ve) {
        Vp vp = c2743ve.a.j;
        return vp != null && vp.b();
    }

    public static final boolean I(boolean z, C2743ve c2743ve) {
        return (!z || c2743ve.a.O().b() || c2743ve.a.o0().equals("interstitial_mb")) ? false : true;
    }

    public static WebResourceResponse r() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.P0)).booleanValue()) {
            return new WebResourceResponse("", "", new ByteArrayInputStream(new byte[0]));
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0040 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void A(android.view.View r8, com.google.android.gms.internal.ads.InterfaceC1679Dc r9, int r10) {
        /*
            r7 = this;
            com.google.android.gms.internal.ads.Cc r9 = (com.google.android.gms.internal.ads.C1673Cc) r9
            com.google.android.gms.internal.ads.zzbxs r0 = r9.g
            boolean r0 = r0.c
            if (r0 == 0) goto Lb6
            boolean r1 = r9.j
            if (r1 != 0) goto Lb6
            if (r10 <= 0) goto Lb6
            if (r0 != 0) goto L12
            goto La0
        L12:
            if (r1 != 0) goto La0
            com.google.android.gms.ads.internal.j r0 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.F r0 = r0.c
            r0 = 1
            r1 = 0
            if (r8 != 0) goto L1d
            goto L78
        L1d:
            boolean r2 = r8.isDrawingCacheEnabled()     // Catch: java.lang.RuntimeException -> L2f
            r8.setDrawingCacheEnabled(r0)     // Catch: java.lang.RuntimeException -> L2f
            android.graphics.Bitmap r3 = r8.getDrawingCache()     // Catch: java.lang.RuntimeException -> L2f
            if (r3 == 0) goto L31
            android.graphics.Bitmap r3 = android.graphics.Bitmap.createBitmap(r3)     // Catch: java.lang.RuntimeException -> L2f
            goto L32
        L2f:
            r2 = move-exception
            goto L38
        L31:
            r3 = r1
        L32:
            r8.setDrawingCacheEnabled(r2)     // Catch: java.lang.RuntimeException -> L36
            goto L3e
        L36:
            r2 = move-exception
            goto L39
        L38:
            r3 = r1
        L39:
            java.lang.String r4 = "Fail to capture the web view"
            com.google.android.gms.ads.internal.util.client.i.f(r4, r2)
        L3e:
            if (r3 != 0) goto L77
            int r2 = r8.getWidth()     // Catch: java.lang.RuntimeException -> L69
            int r3 = r8.getHeight()     // Catch: java.lang.RuntimeException -> L69
            if (r2 == 0) goto L6b
            if (r3 != 0) goto L4d
            goto L6b
        L4d:
            int r4 = r8.getWidth()     // Catch: java.lang.RuntimeException -> L69
            int r5 = r8.getHeight()     // Catch: java.lang.RuntimeException -> L69
            android.graphics.Bitmap$Config r6 = android.graphics.Bitmap.Config.RGB_565     // Catch: java.lang.RuntimeException -> L69
            android.graphics.Bitmap r4 = android.graphics.Bitmap.createBitmap(r4, r5, r6)     // Catch: java.lang.RuntimeException -> L69
            android.graphics.Canvas r5 = new android.graphics.Canvas     // Catch: java.lang.RuntimeException -> L69
            r5.<init>(r4)     // Catch: java.lang.RuntimeException -> L69
            r6 = 0
            r8.layout(r6, r6, r2, r3)     // Catch: java.lang.RuntimeException -> L69
            r8.draw(r5)     // Catch: java.lang.RuntimeException -> L69
            r1 = r4
            goto L78
        L69:
            r2 = move-exception
            goto L71
        L6b:
            java.lang.String r2 = "Width or height of view is zero"
            com.google.android.gms.ads.internal.util.client.i.h(r2)     // Catch: java.lang.RuntimeException -> L69
            goto L78
        L71:
            java.lang.String r3 = "Fail to capture the webview"
            com.google.android.gms.ads.internal.util.client.i.f(r3, r2)
            goto L78
        L77:
            r1 = r3
        L78:
            if (r1 != 0) goto L80
            java.lang.String r0 = "Failed to capture the webview bitmap."
            com.google.android.gms.internal.ads.AbstractC2096gb.i(r0)
            goto La0
        L80:
            r9.j = r0
            com.google.android.gms.internal.ads.Qv r0 = new com.google.android.gms.internal.ads.Qv
            r2 = 12
            r0.<init>(r2, r9, r1)
            android.os.Looper r1 = android.os.Looper.getMainLooper()
            java.lang.Thread r1 = r1.getThread()
            java.lang.Thread r2 = java.lang.Thread.currentThread()
            if (r1 == r2) goto L9b
            r0.run()
            goto La0
        L9b:
            com.google.android.gms.internal.ads.jd r1 = com.google.android.gms.internal.ads.AbstractC2270kd.a
            r1.execute(r0)
        La0:
            com.google.android.gms.internal.ads.zzbxs r0 = r9.g
            boolean r0 = r0.c
            if (r0 == 0) goto Lb6
            boolean r0 = r9.j
            if (r0 != 0) goto Lb6
            com.google.android.gms.ads.internal.util.B r0 = com.google.android.gms.ads.internal.util.F.l
            com.google.android.gms.internal.ads.Td r1 = new com.google.android.gms.internal.ads.Td
            r1.<init>(r7, r8, r9, r10)
            r8 = 100
            r0.postDelayed(r1, r8)
        Lb6:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1669Be.A(android.view.View, com.google.android.gms.internal.ads.Dc, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:101:0x0220 A[Catch: all -> 0x0228, TryCatch #6 {all -> 0x0228, blocks: (B:99:0x020e, B:101:0x0220, B:104:0x022a), top: B:146:0x020e }] */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0286 A[Catch: NoClassDefFoundError -> 0x001c, Exception -> 0x001f, TryCatch #16 {Exception -> 0x001f, NoClassDefFoundError -> 0x001c, blocks: (B:3:0x000c, B:5:0x0019, B:10:0x0022, B:12:0x0032, B:14:0x0039, B:16:0x0045, B:18:0x0062, B:20:0x007e, B:22:0x0095, B:24:0x009b, B:28:0x00a4, B:31:0x00be, B:34:0x00c8, B:36:0x00d6, B:39:0x00ed, B:58:0x0154, B:59:0x017c, B:131:0x02de, B:135:0x02f2, B:137:0x02f8, B:139:0x0306, B:105:0x022d, B:106:0x0259, B:107:0x0285, B:92:0x01d9, B:38:0x00e2, B:108:0x0286, B:110:0x0290, B:112:0x0296, B:114:0x0299, B:115:0x029a, B:116:0x02b7, B:118:0x02ba, B:119:0x02bb, B:121:0x02c9, B:125:0x02d6, B:128:0x02d9, B:117:0x02b8, B:113:0x0297), top: B:160:0x000c, inners: #15, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:131:0x02de A[Catch: NoClassDefFoundError -> 0x001c, Exception -> 0x001f, TryCatch #16 {Exception -> 0x001f, NoClassDefFoundError -> 0x001c, blocks: (B:3:0x000c, B:5:0x0019, B:10:0x0022, B:12:0x0032, B:14:0x0039, B:16:0x0045, B:18:0x0062, B:20:0x007e, B:22:0x0095, B:24:0x009b, B:28:0x00a4, B:31:0x00be, B:34:0x00c8, B:36:0x00d6, B:39:0x00ed, B:58:0x0154, B:59:0x017c, B:131:0x02de, B:135:0x02f2, B:137:0x02f8, B:139:0x0306, B:105:0x022d, B:106:0x0259, B:107:0x0285, B:92:0x01d9, B:38:0x00e2, B:108:0x0286, B:110:0x0290, B:112:0x0296, B:114:0x0299, B:115:0x029a, B:116:0x02b7, B:118:0x02ba, B:119:0x02bb, B:121:0x02c9, B:125:0x02d6, B:128:0x02d9, B:117:0x02b8, B:113:0x0297), top: B:160:0x000c, inners: #15, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:133:0x02ee  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00be A[Catch: NoClassDefFoundError -> 0x001c, Exception -> 0x001f, TRY_ENTER, TryCatch #16 {Exception -> 0x001f, NoClassDefFoundError -> 0x001c, blocks: (B:3:0x000c, B:5:0x0019, B:10:0x0022, B:12:0x0032, B:14:0x0039, B:16:0x0045, B:18:0x0062, B:20:0x007e, B:22:0x0095, B:24:0x009b, B:28:0x00a4, B:31:0x00be, B:34:0x00c8, B:36:0x00d6, B:39:0x00ed, B:58:0x0154, B:59:0x017c, B:131:0x02de, B:135:0x02f2, B:137:0x02f8, B:139:0x0306, B:105:0x022d, B:106:0x0259, B:107:0x0285, B:92:0x01d9, B:38:0x00e2, B:108:0x0286, B:110:0x0290, B:112:0x0296, B:114:0x0299, B:115:0x029a, B:116:0x02b7, B:118:0x02ba, B:119:0x02bb, B:121:0x02c9, B:125:0x02d6, B:128:0x02d9, B:117:0x02b8, B:113:0x0297), top: B:160:0x000c, inners: #15, #18 }] */
    /* JADX WARN: Type inference failed for: r17v0 */
    /* JADX WARN: Type inference failed for: r17v1 */
    /* JADX WARN: Type inference failed for: r17v2, types: [java.io.InputStream] */
    /* JADX WARN: Type inference failed for: r17v3 */
    /* JADX WARN: Type inference failed for: r2v24, types: [com.google.android.gms.internal.ads.l6, java.io.InputStream] */
    /* JADX WARN: Type inference failed for: r6v1, types: [android.os.ParcelFileDescriptor$AutoCloseInputStream, java.io.InputStream] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.webkit.WebResourceResponse K(java.lang.String r21, java.util.Map r22) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 794
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1669Be.K(java.lang.String, java.util.Map):android.webkit.WebResourceResponse");
    }

    public final void M() {
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe;
        C1732Mb c1732Mb;
        InterfaceC1681De interfaceC1681De = this.g;
        C2743ve c2743ve = this.a;
        if (interfaceC1681De != null && ((this.A && this.C <= 0) || this.B || this.m)) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue() && (c1732Mb = (viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a).L) != null) {
                AbstractC2096gb.h((B7) c1732Mb.c, viewTreeObserverOnGlobalLayoutListenerC2829xe.J, "awfllc");
            }
            InterfaceC1681De interfaceC1681De2 = this.g;
            boolean z = false;
            if (!this.B && !this.m) {
                z = true;
            }
            interfaceC1681De2.A(this.o, this.n, this.p, z);
            this.g = null;
        }
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe2 = c2743ve.a;
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe2.K == null) {
            C1732Mb c1732Mb2 = viewTreeObserverOnGlobalLayoutListenerC2829xe2.L;
            c1732Mb2.getClass();
            C2902z7 c2902z7D = B7.d();
            viewTreeObserverOnGlobalLayoutListenerC2829xe2.K = c2902z7D;
            ((HashMap) c1732Mb2.b).put("native:view_load", c2902z7D);
        }
    }

    public final void S() {
        InterfaceC1679Dc interfaceC1679Dc = this.y;
        if (interfaceC1679Dc != null) {
            C1673Cc c1673Cc = (C1673Cc) interfaceC1679Dc;
            synchronized (c1673Cc.h) {
                c1673Cc.b.keySet();
                Tv tvE = AbstractC2025es.E(Collections.EMPTY_MAP);
                D9 d9 = new D9(c1673Cc, 1);
                C2227jd c2227jd = AbstractC2270kd.g;
                C2846xv c2846xvN = AbstractC2025es.N(tvE, d9, c2227jd);
                com.google.common.util.concurrent.e eVarO = AbstractC2025es.O(c2846xvN, 10L, TimeUnit.SECONDS, AbstractC2270kd.d);
                c2846xvN.a(new Qv(0, c2846xvN, new Ts(eVarO, 12)), c2227jd);
                C1673Cc.l.add(eVarO);
            }
            this.y = null;
        }
        ViewOnAttachStateChangeListenerC2571re viewOnAttachStateChangeListenerC2571re = this.G;
        if (viewOnAttachStateChangeListenerC2571re != null) {
            this.a.removeOnAttachStateChangeListener(viewOnAttachStateChangeListenerC2571re);
        }
        synchronized (this.d) {
            try {
                this.c.clear();
                this.e = null;
                this.f = null;
                this.g = null;
                this.h = null;
                this.i = null;
                this.j = null;
                this.l = false;
                this.q = false;
                this.r = false;
                this.s = false;
                this.u = null;
                this.w = null;
                this.v = null;
                C2397nb c2397nb = this.x;
                if (c2397nb != null) {
                    c2397nb.E(true);
                    this.x = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void X(Uri uri) {
        com.google.android.gms.ads.internal.util.A.l("Received GMSG: ".concat(String.valueOf(uri)));
        HashMap map = this.c;
        String path = uri.getPath();
        List list = (List) map.get(path);
        if (path == null || list == null) {
            com.google.android.gms.ads.internal.util.A.l("No GMSG handler found for GMSG: ".concat(String.valueOf(uri)));
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G6)).booleanValue() || com.google.android.gms.ads.internal.j.C.h.c() == null) {
                return;
            }
            AbstractC2270kd.a.execute(new RunnableC1989e((path == null || path.length() < 2) ? "null" : path.substring(1), 20));
            return;
        }
        String encodedQuery = uri.getEncodedQuery();
        C2601s7 c2601s7 = AbstractC2773w7.G5;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && this.E.contains(path) && encodedQuery != null) {
            if (encodedQuery.length() >= ((Integer) rVar.c.a(AbstractC2773w7.I5)).intValue()) {
                com.google.android.gms.ads.internal.util.A.l("Parsing gmsg query params on BG thread: ".concat(path));
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                f.getClass();
                RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(new androidx.camera.core.impl.utils.executor.c(uri, 6));
                f.k.execute(runnableFutureC2161hw);
                runnableFutureC2161hw.a(new Qv(0, runnableFutureC2161hw, new androidx.work.impl.model.i(this, list, path, uri, 3)), AbstractC2270kd.f);
                return;
            }
        }
        com.google.android.gms.ads.internal.util.F f2 = com.google.android.gms.ads.internal.j.C.c;
        v(com.google.android.gms.ads.internal.util.F.m(uri), list, path);
    }

    public final void a(String str, InterfaceC2389n9 interfaceC2389n9) {
        synchronized (this.d) {
            try {
                HashMap map = this.c;
                List copyOnWriteArrayList = (List) map.get(str);
                if (copyOnWriteArrayList == null) {
                    copyOnWriteArrayList = new CopyOnWriteArrayList();
                    map.put(str, copyOnWriteArrayList);
                }
                copyOnWriteArrayList.add(interfaceC2389n9);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void a0(int i, int i2) {
        C2526qb c2526qb = this.v;
        if (c2526qb != null) {
            c2526qb.E(i, i2);
        }
        C2397nb c2397nb = this.x;
        if (c2397nb != null) {
            synchronized (c2397nb.l) {
                c2397nb.f = i;
                c2397nb.g = i2;
            }
        }
    }

    public final void b(C2830xf c2830xf, C2107gm c2107gm, C2584rr c2584rr) {
        j("/click");
        if (c2107gm != null && c2584rr != null) {
            a("/click", new Ji(this.k, c2830xf, c2584rr, c2107gm));
            return;
        }
        InterfaceC2447oi interfaceC2447oi = this.k;
        C2175i9 c2175i9 = AbstractC2346m9.a;
        a("/click", new C2217j9(0, interfaceC2447oi, c2830xf));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c() {
        InterfaceC2447oi interfaceC2447oi = this.k;
        if (interfaceC2447oi != null) {
            interfaceC2447oi.c();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c0() {
        InterfaceC2447oi interfaceC2447oi = this.k;
        if (interfaceC2447oi != null) {
            interfaceC2447oi.c0();
        }
    }

    public final void d(C2830xf c2830xf, C2107gm c2107gm, Hk hk) {
        j("/open");
        a("/open", new C2689u9(this.w, this.x, c2107gm, hk, c2830xf));
    }

    public final void j(String str) {
        synchronized (this.d) {
            try {
                List list = (List) this.c.get(str);
                if (list == null) {
                    return;
                }
                list.clear();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void m0() {
        InterfaceC1679Dc interfaceC1679Dc = this.y;
        if (interfaceC1679Dc != null) {
            C2743ve c2743ve = this.a;
            ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            if (viewTreeObserverOnGlobalLayoutListenerC2829xe.isAttachedToWindow()) {
                A(viewTreeObserverOnGlobalLayoutListenerC2829xe, interfaceC1679Dc, 10);
                return;
            }
            ViewOnAttachStateChangeListenerC2571re viewOnAttachStateChangeListenerC2571re = this.G;
            if (viewOnAttachStateChangeListenerC2571re != null) {
                c2743ve.removeOnAttachStateChangeListener(viewOnAttachStateChangeListenerC2571re);
            }
            ViewOnAttachStateChangeListenerC2571re viewOnAttachStateChangeListenerC2571re2 = new ViewOnAttachStateChangeListenerC2571re(this, interfaceC1679Dc);
            this.G = viewOnAttachStateChangeListenerC2571re2;
            c2743ve.addOnAttachStateChangeListener(viewOnAttachStateChangeListenerC2571re2);
        }
    }

    public final boolean o() {
        boolean z;
        synchronized (this.d) {
            z = this.r;
        }
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        InterfaceC1582a interfaceC1582a = this.e;
        if (interfaceC1582a != null) {
            interfaceC1582a.onAdClicked();
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onLoadResource(WebView webView, String str) {
        com.google.android.gms.ads.internal.util.A.l("Loading resource: ".concat(String.valueOf(str)));
        Uri uri = Uri.parse(str);
        if ("gmsg".equalsIgnoreCase(uri.getScheme()) && "mobileads.google.com".equalsIgnoreCase(uri.getHost())) {
            X(uri);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onPageFinished(WebView webView, String str) {
        Toolbar toolbar;
        synchronized (this.d) {
            try {
                C2743ve c2743ve = this.a;
                if (c2743ve.a.B()) {
                    com.google.android.gms.ads.internal.util.A.l("Blank page loaded, 1...");
                    c2743ve.s();
                    return;
                }
                this.A = true;
                InterfaceC1687Ee interfaceC1687Ee = this.h;
                if (interfaceC1687Ee != null) {
                    interfaceC1687Ee.mo20zza();
                    this.h = null;
                }
                M();
                C2743ve c2743ve2 = this.a;
                if (c2743ve2.a.Q() != null) {
                    if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Tb)).booleanValue() || (toolbar = c2743ve2.a.Q().v) == null) {
                        return;
                    }
                    toolbar.setSubtitle(str);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedError(WebView webView, int i, String str, String str2) {
        this.m = true;
        this.n = i;
        this.o = str;
        this.p = str2;
    }

    @Override // android.webkit.WebViewClient
    public final boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
        final boolean zDidCrash = renderProcessGoneDetail.didCrash();
        final int iRendererPriorityAtExit = renderProcessGoneDetail.rendererPriorityAtExit();
        C2743ve c2743ve = this.a;
        if (c2743ve.c.compareAndSet(false, true)) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.R0)).booleanValue()) {
                return false;
            }
            ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
            if (viewTreeObserverOnGlobalLayoutListenerC2829xe.getParent() instanceof ViewGroup) {
                ((ViewGroup) viewTreeObserverOnGlobalLayoutListenerC2829xe.getParent()).removeView(viewTreeObserverOnGlobalLayoutListenerC2829xe);
            }
            viewTreeObserverOnGlobalLayoutListenerC2829xe.destroy();
            InterfaceC2386n6 interfaceC2386n6 = new InterfaceC2386n6() { // from class: com.google.android.gms.internal.ads.we
                @Override // com.google.android.gms.internal.ads.InterfaceC2386n6
                public final void c(C2301l7 c2301l7) {
                    int i = ViewTreeObserverOnGlobalLayoutListenerC2829xe.m1;
                    Z6 z6W = C1823a7.w();
                    boolean zX = ((C1823a7) z6W.b).x();
                    boolean z = zDidCrash;
                    if (zX != z) {
                        z6W.e();
                        C1823a7.y((C1823a7) z6W.b, z);
                    }
                    z6W.e();
                    C1823a7.z((C1823a7) z6W.b, iRendererPriorityAtExit);
                    C1823a7 c1823a7 = (C1823a7) z6W.c();
                    c2301l7.e();
                    C2344m7.C((C2344m7) c2301l7.b, c1823a7);
                }
            };
            C2429o6 c2429o6 = viewTreeObserverOnGlobalLayoutListenerC2829xe.k1;
            c2429o6.a(interfaceC2386n6);
            c2429o6.b(10003);
        }
        return true;
    }

    public final void q(InterfaceC1582a interfaceC1582a, InterfaceC1999e9 interfaceC1999e9, com.google.android.gms.ads.internal.overlay.j jVar, InterfaceC2043f9 interfaceC2043f9, com.google.android.gms.ads.internal.overlay.c cVar, boolean z, C2475p9 c2475p9, com.google.android.gms.ads.internal.a aVar, Os os, InterfaceC1679Dc interfaceC1679Dc, C2107gm c2107gm, C2584rr c2584rr, Hk hk, C2432o9 c2432o9, InterfaceC2447oi interfaceC2447oi, C2861y9 c2861y9, C1956d9 c1956d9, C2432o9 c2432o92, C2830xf c2830xf) {
        Vp vp;
        C2743ve c2743ve = this.a;
        com.google.android.gms.ads.internal.a aVar2 = aVar == null ? new com.google.android.gms.ads.internal.a(c2743ve.getContext(), interfaceC1679Dc) : aVar;
        this.x = new C2397nb(c2743ve, os);
        this.y = interfaceC1679Dc;
        C2601s7 c2601s7 = AbstractC2773w7.W0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            a("/adMetadata", new C1956d9(interfaceC1999e9, 0));
        }
        if (interfaceC2043f9 != null) {
            a("/appEvent", new C1956d9(interfaceC2043f9, 1));
        }
        a("/backButton", AbstractC2346m9.j);
        a("/refresh", AbstractC2346m9.k);
        a("/canOpenApp", AbstractC2346m9.b);
        a("/canOpenURLs", AbstractC2346m9.a);
        a("/canOpenIntents", AbstractC2346m9.c);
        a("/close", AbstractC2346m9.d);
        a("/customClose", AbstractC2346m9.e);
        a("/instrument", AbstractC2346m9.n);
        a("/delayPageLoaded", AbstractC2346m9.p);
        a("/delayPageClosed", AbstractC2346m9.q);
        a("/getLocationInfo", AbstractC2346m9.r);
        a("/log", AbstractC2346m9.g);
        a("/mraid", new C2560r9(aVar2, this.x, os));
        C2526qb c2526qb = this.v;
        if (c2526qb != null) {
            a("/mraidLoaded", c2526qb);
        }
        com.google.android.gms.ads.internal.a aVar3 = aVar2;
        a("/open", new C2689u9(aVar3, this.x, c2107gm, hk, c2830xf));
        a("/precache", new C2175i9(26));
        a("/touch", AbstractC2346m9.i);
        a("/video", AbstractC2346m9.l);
        a("/videoMeta", AbstractC2346m9.m);
        if (c2107gm == null || c2584rr == null) {
            a("/click", new C2217j9(0, interfaceC2447oi, c2830xf));
            a("/httpTrack", AbstractC2346m9.f);
        } else {
            a("/click", new Ji(interfaceC2447oi, c2830xf, c2584rr, c2107gm));
            a("/httpTrack", new C2217j9(6, c2584rr, c2107gm));
        }
        boolean zE = com.google.android.gms.ads.internal.j.C.y.e(c2743ve.getContext());
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
        if (zE) {
            HashMap map = new HashMap();
            Vp vp2 = viewTreeObserverOnGlobalLayoutListenerC2829xe.j;
            if (vp2 != null) {
                map = vp2.w0;
            }
            a("/logScionEvent", new C2217j9(1, c2743ve.getContext(), map));
        }
        if (c2475p9 != null) {
            a("/setInterstitialProperties", new C1956d9(c2475p9, 2));
        }
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (c2432o9 != null && ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.U8)).booleanValue()) {
            a("/inspectorNetworkExtras", c2432o9);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.n9)).booleanValue() && c2861y9 != null) {
            a("/shareSheet", c2861y9);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.s9)).booleanValue() && c1956d9 != null) {
            a("/inspectorOutOfContextTest", c1956d9);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.w9)).booleanValue() && c2432o92 != null) {
            a("/inspectorStorage", c2432o92);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.yb)).booleanValue()) {
            a("/bindPlayStoreOverlay", AbstractC2346m9.u);
            a("/presentPlayStoreOverlay", AbstractC2346m9.v);
            a("/expandPlayStoreOverlay", AbstractC2346m9.w);
            a("/collapsePlayStoreOverlay", AbstractC2346m9.x);
            a("/closePlayStoreOverlay", AbstractC2346m9.y);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.s3)).booleanValue()) {
            a("/setPAIDPersonalizationEnabled", AbstractC2346m9.A);
            a("/resetPAID", AbstractC2346m9.z);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Sb)).booleanValue() && (vp = viewTreeObserverOnGlobalLayoutListenerC2829xe.j) != null && vp.r0) {
            a("/writeToLocalStorage", AbstractC2346m9.B);
            a("/clearLocalStorageKeys", AbstractC2346m9.C);
        }
        this.e = interfaceC1582a;
        this.f = jVar;
        this.i = interfaceC1999e9;
        this.j = interfaceC2043f9;
        this.u = cVar;
        this.w = aVar3;
        this.k = interfaceC2447oi;
        this.z = hk;
        this.l = z;
    }

    public final void r0(zzc zzcVar, boolean z, boolean z2, String str) {
        boolean z3;
        C2743ve c2743ve = this.a;
        boolean zT = c2743ve.a.T();
        boolean z4 = false;
        boolean z5 = I(zT, c2743ve) || z2;
        if (z5 || !z) {
            z3 = zT;
            z4 = true;
        } else {
            z3 = zT;
        }
        z0(new AdOverlayInfoParcel(zzcVar, z5 ? null : this.e, z3 ? null : this.f, this.u, c2743ve.a.e, c2743ve, z4 ? null : this.k, str));
    }

    /* JADX WARN: Code restructure failed: missing block: B:34:0x00ee, code lost:
    
        r14 = r3.getContentType();
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00f6, code lost:
    
        r4 = "";
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00fa, code lost:
    
        if (android.text.TextUtils.isEmpty(r14) == false) goto L38;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00fc, code lost:
    
        r6 = "";
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00fe, code lost:
    
        r6 = r14.split(";")[0].trim();
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0109, code lost:
    
        r14 = r3.getContentType();
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0111, code lost:
    
        if (android.text.TextUtils.isEmpty(r14) == false) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0113, code lost:
    
        r7 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0115, code lost:
    
        r14 = r14.split(";");
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x011a, code lost:
    
        if (r14.length != 1) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x011d, code lost:
    
        r0 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x011f, code lost:
    
        if (r0 >= r14.length) goto L95;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x012d, code lost:
    
        if (r14[r0].trim().startsWith("charset") == false) goto L96;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x012f, code lost:
    
        r1 = r14[r0].trim().split(com.j256.ormlite.stmt.query.SimpleComparison.EQUAL_TO_OPERATION);
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x013c, code lost:
    
        if (r1.length <= 1) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x013e, code lost:
    
        r4 = r1[1].trim();
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0145, code lost:
    
        r0 = r0 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0148, code lost:
    
        r14 = r3.getHeaderFields();
        r10 = new java.util.HashMap(r14.size());
        r14 = r14.entrySet().iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0161, code lost:
    
        if (r14.hasNext() == false) goto L85;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0163, code lost:
    
        r0 = r14.next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x016d, code lost:
    
        if (r0.getKey() == null) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0173, code lost:
    
        if (r0.getValue() == null) goto L91;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x017f, code lost:
    
        if (r0.getValue().isEmpty() != false) goto L92;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0181, code lost:
    
        r10.put(r0.getKey(), r0.getValue().get(0));
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0197, code lost:
    
        r13 = com.google.android.gms.ads.internal.j.C.f;
        r8 = r3.getResponseCode();
        r9 = r3.getResponseMessage();
        r11 = r3.getInputStream();
        r13.getClass();
        r5 = new android.webkit.WebResourceResponse(r6, r7, r8, r9, r10, r11);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.webkit.WebResourceResponse s(java.lang.String r13, java.util.Map r14) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 458
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1669Be.s(java.lang.String, java.util.Map):android.webkit.WebResourceResponse");
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.webkit.WebViewClient
    public final WebResourceResponse shouldInterceptRequest(WebView webView, WebResourceRequest webResourceRequest) {
        String str;
        if (webResourceRequest != null && webResourceRequest.getUrl() != null) {
            String string = webResourceRequest.getUrl().toString();
            Map<String, String> requestHeaders = webResourceRequest.getRequestHeaders();
            if (!(webView instanceof InterfaceC2529qe)) {
                com.google.android.gms.ads.internal.util.client.i.h("Tried to intercept request from a WebView that wasn't an AdWebView.");
                return null;
            }
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) webView;
            InterfaceC1679Dc interfaceC1679Dc = this.y;
            if (interfaceC1679Dc != null) {
                ((C1673Cc) interfaceC1679Dc).a(string, requestHeaders, 1);
            }
            if (!"mraid.js".equalsIgnoreCase(new File(string).getName())) {
                if (requestHeaders == null) {
                    requestHeaders = Collections.EMPTY_MAP;
                }
                return K(string, requestHeaders);
            }
            if (interfaceC2529qe.L() != null) {
                C1669Be c1669BeL = interfaceC2529qe.L();
                synchronized (c1669BeL.d) {
                    c1669BeL.l = false;
                    c1669BeL.q = true;
                    AbstractC2270kd.f.execute(new RunnableC1989e(c1669BeL, 19));
                }
            }
            if (interfaceC2529qe.O().b()) {
                str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U);
            } else if (interfaceC2529qe.T()) {
                str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T);
            } else {
                str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.S);
            }
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            com.google.android.gms.ads.internal.util.F f = jVar.c;
            Context context = interfaceC2529qe.getContext();
            String str2 = interfaceC2529qe.l().a;
            try {
                HashMap map = new HashMap();
                map.put("User-Agent", jVar.c.y(context, str2));
                map.put("Cache-Control", "max-stale=3600");
                new com.google.android.gms.ads.internal.util.q(context);
                com.google.android.gms.ads.internal.util.o oVarA = com.google.android.gms.ads.internal.util.q.a(0, str, map, null);
                String str3 = (String) oVarA.a.get(60L, TimeUnit.SECONDS);
                if (str3 != null) {
                    return new WebResourceResponse("application/javascript", "UTF-8", new ByteArrayInputStream(str3.getBytes("UTF-8")));
                }
            } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
                com.google.android.gms.ads.internal.util.client.i.i("Could not fetch MRAID JS.", e);
            }
        }
        return null;
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideKeyEvent(WebView webView, KeyEvent keyEvent) {
        int keyCode = keyEvent.getKeyCode();
        if (keyCode == 79 || keyCode == 222) {
            return true;
        }
        switch (keyCode) {
            case 85:
            case 86:
            case 87:
            case 88:
            case 89:
            case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
            case 91:
                return true;
            default:
                switch (keyCode) {
                    case 126:
                    case 127:
                    case 128:
                    case 129:
                    case 130:
                        return true;
                    default:
                        return false;
                }
        }
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, String str) {
        com.google.android.gms.ads.internal.util.A.l("AdWebView shouldOverrideUrlLoading: ".concat(String.valueOf(str)));
        Uri uriA = Uri.parse(str);
        if ("gmsg".equalsIgnoreCase(uriA.getScheme()) && "mobileads.google.com".equalsIgnoreCase(uriA.getHost())) {
            X(uriA);
            return true;
        }
        boolean z = this.l;
        C2743ve c2743ve = this.a;
        if (z && webView == c2743ve.a) {
            String scheme = uriA.getScheme();
            if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                InterfaceC1582a interfaceC1582a = this.e;
                if (interfaceC1582a != null) {
                    interfaceC1582a.onAdClicked();
                    InterfaceC1679Dc interfaceC1679Dc = this.y;
                    if (interfaceC1679Dc != null) {
                        ((C1673Cc) interfaceC1679Dc).b(str);
                    }
                    this.e = null;
                }
                InterfaceC2447oi interfaceC2447oi = this.k;
                if (interfaceC2447oi != null) {
                    interfaceC2447oi.c0();
                    this.k = null;
                }
                return super.shouldOverrideUrlLoading(webView, str);
            }
        }
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe2 = c2743ve.a;
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe.willNotDraw()) {
            com.google.android.gms.ads.internal.util.client.i.h("AdWebView unable to handle URL: ".concat(String.valueOf(str)));
            return true;
        }
        try {
            P4 p4 = viewTreeObserverOnGlobalLayoutListenerC2829xe2.b;
            C2067fq c2067fq = viewTreeObserverOnGlobalLayoutListenerC2829xe2.c;
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Xb)).booleanValue() || c2067fq == null) {
                if (p4 != null && p4.c(uriA)) {
                    uriA = p4.a(uriA, c2743ve.getContext(), c2743ve, c2743ve.zzi());
                }
            } else if (p4 != null && p4.c(uriA)) {
                uriA = c2067fq.a(uriA, c2743ve.getContext(), c2743ve, c2743ve.zzi());
            }
        } catch (zzavm unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Unable to append parameter to URL: ".concat(String.valueOf(str)));
        }
        com.google.android.gms.ads.internal.a aVar = this.w;
        if (aVar == null || aVar.b()) {
            r0(new zzc("android.intent.action.VIEW", uriA.toString(), null, null, null, null, null, null), true, false, viewTreeObserverOnGlobalLayoutListenerC2829xe2.w());
        } else {
            aVar.a(str);
        }
        return true;
    }

    public final void v(Map map, List list, String str) {
        if (com.google.android.gms.ads.internal.util.A.m()) {
            com.google.android.gms.ads.internal.util.A.l("Received GMSG: ".concat(str));
            for (String str2 : map.keySet()) {
                com.google.android.gms.ads.internal.util.A.l("  " + str2 + ": " + ((String) map.get(str2)));
            }
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            ((InterfaceC2389n9) it2.next()).e(this.a, map);
        }
    }

    public final void z0(AdOverlayInfoParcel adOverlayInfoParcel) {
        zzc zzcVar;
        C2397nb c2397nb = this.x;
        if (c2397nb != null) {
            synchronized (c2397nb.l) {
                z = c2397nb.s != null;
            }
        }
        assistantMode.utils.studiableMetadata.b bVar = com.google.android.gms.ads.internal.j.C.b;
        assistantMode.utils.studiableMetadata.b.a0(this.a.getContext(), adOverlayInfoParcel, !z, this.z);
        InterfaceC1679Dc interfaceC1679Dc = this.y;
        if (interfaceC1679Dc != null) {
            String str = adOverlayInfoParcel.l;
            if (str == null && (zzcVar = adOverlayInfoParcel.a) != null) {
                str = zzcVar.b;
            }
            ((C1673Cc) interfaceC1679Dc).b(str);
        }
    }

    @Override // android.webkit.WebViewClient
    public final WebResourceResponse shouldInterceptRequest(WebView webView, String str) {
        return K(str, Collections.EMPTY_MAP);
    }
}
