package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Canvas;
import android.net.Uri;
import android.os.Looper;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.DownloadListener;
import android.webkit.ValueCallback;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.widget.C0110t;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.xe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewTreeObserverOnGlobalLayoutListenerC2829xe extends WebView implements DownloadListener, ViewTreeObserver.OnGlobalLayoutListener, InterfaceC2529qe {
    public static final /* synthetic */ int m1 = 0;
    public BinderC2915ze A;
    public boolean B;
    public boolean C;
    public InterfaceC2517q8 D;
    public Qj E;
    public T5 F;
    public int G;
    public int H;
    public C2902z7 I;
    public final C2902z7 J;
    public C2902z7 K;
    public final C1732Mb L;
    public int M;
    public com.google.android.gms.ads.internal.overlay.d V;
    public boolean W;
    public final C1693Fe a;
    public final P4 b;
    public final C2067fq c;
    public final C0110t c1;
    public final J7 d;
    public int d1;
    public final VersionInfoParcel e;
    public int e1;
    public C2881yn f;
    public int f1;
    public final androidx.work.impl.model.c g;
    public int g1;
    public final DisplayMetrics h;
    public int h1;
    public final float i;
    public HashMap i1;
    public Vp j;
    public final WindowManager j1;
    public Xp k;
    public final C2429o6 k1;
    public boolean l;
    public boolean l1;
    public boolean m;
    public C1669Be n;
    public com.google.android.gms.ads.internal.overlay.d o;
    public C2665tm p;
    public C2622sm q;
    public com.bumptech.glide.load.engine.cache.f r;
    public final String s;
    public boolean t;
    public boolean u;
    public boolean v;
    public boolean w;
    public Boolean x;
    public boolean y;
    public final String z;

    public ViewTreeObserverOnGlobalLayoutListenerC2829xe(C1693Fe c1693Fe, com.bumptech.glide.load.engine.cache.f fVar, String str, boolean z, P4 p4, J7 j7, VersionInfoParcel versionInfoParcel, C2881yn c2881yn, androidx.work.impl.model.c cVar, C2429o6 c2429o6, Vp vp, Xp xp, C2067fq c2067fq) {
        Xp xp2;
        String str2;
        com.google.android.datatransport.cct.internal.s sVarC;
        super(c1693Fe);
        this.l = false;
        this.m = false;
        this.y = true;
        this.z = "";
        this.d1 = -1;
        this.e1 = -1;
        this.f1 = -1;
        this.g1 = -1;
        this.h1 = -1;
        this.a = c1693Fe;
        this.r = fVar;
        this.s = str;
        this.v = z;
        this.b = p4;
        this.c = c2067fq;
        this.d = j7;
        this.e = versionInfoParcel;
        this.f = c2881yn;
        this.g = cVar;
        WindowManager windowManager = (WindowManager) getContext().getSystemService("window");
        this.j1 = windowManager;
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        DisplayMetrics displayMetrics = new DisplayMetrics();
        windowManager.getDefaultDisplay().getMetrics(displayMetrics);
        this.h = displayMetrics;
        this.i = displayMetrics.density;
        this.k1 = c2429o6;
        this.j = vp;
        this.k = xp;
        this.c1 = new C0110t(c1693Fe.a, this, this);
        this.l1 = false;
        setBackgroundColor(0);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Cb)).booleanValue()) {
            setSoundEffectsEnabled(false);
        }
        WebSettings settings = getSettings();
        settings.setAllowFileAccess(false);
        try {
            settings.setJavaScriptEnabled(true);
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to enable Javascript.", e);
        }
        settings.setSavePassword(false);
        settings.setSupportMultipleWindows(true);
        settings.setJavaScriptCanOpenWindowsAutomatically(true);
        C2601s7 c2601s7 = AbstractC2773w7.Bb;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            settings.setMixedContentMode(1);
        } else {
            settings.setMixedContentMode(2);
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.dd)).booleanValue()) {
            settings.setGeolocationEnabled(false);
        }
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        settings.setUserAgentString(jVar.c.y(c1693Fe, versionInfoParcel.a));
        Context context = getContext();
        com.google.android.gms.internal.mlkit_vision_common.X2.d(context, new com.google.android.gms.ads.internal.util.y(settings, false, context, 1));
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMediaPlaybackRequiresUserGesture(false);
        setDownloadListener(this);
        X();
        addJavascriptInterface(new C1663Ae(this, new Ts(this, 15)), "googleAdsJsInterface");
        removeJavascriptInterface("accessibility");
        removeJavascriptInterface("accessibilityTraversal");
        C1732Mb c1732Mb = this.L;
        if (c1732Mb != null && (sVarC = jVar.h.c()) != null) {
            ((ArrayBlockingQueue) sVarC.b).offer((B7) c1732Mb.c);
        }
        B7 b7 = new B7(this.s);
        C1732Mb c1732Mb2 = new C1732Mb(b7);
        this.L = c1732Mb2;
        synchronized (b7.c) {
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.T1)).booleanValue() && (xp2 = this.k) != null && (str2 = xp2.b) != null) {
            b7.b("gqi", str2);
        }
        C2902z7 c2902z7D = B7.d();
        this.J = c2902z7D;
        ((HashMap) c1732Mb2.b).put("native:view_create", c2902z7D);
        this.K = null;
        this.I = null;
        if (androidx.emoji2.text.r.b == null) {
            androidx.emoji2.text.r.b = new androidx.emoji2.text.r();
        }
        androidx.emoji2.text.r rVar2 = androidx.emoji2.text.r.b;
        rVar2.getClass();
        com.google.android.gms.ads.internal.util.A.l("Updating user agent.");
        String defaultUserAgent = WebSettings.getDefaultUserAgent(c1693Fe);
        if (!defaultUserAgent.equals(rVar2.a)) {
            if (com.google.android.gms.common.d.a(c1693Fe) == null) {
                c1693Fe.getSharedPreferences("admob_user_agent", 0).edit().putString("user_agent", WebSettings.getDefaultUserAgent(c1693Fe)).apply();
            }
            rVar2.a = defaultUserAgent;
        }
        com.google.android.gms.ads.internal.util.A.l("User agent is updated.");
        jVar.h.j.incrementAndGet();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C2067fq A0() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized boolean B() {
        return this.u;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void B0(C2665tm c2665tm) {
        this.p = c2665tm;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void C(boolean z, int i, String str, boolean z2, boolean z3) {
        C1669Be c1669Be = this.n;
        C2743ve c2743ve = c1669Be.a;
        boolean zT = c2743ve.a.T();
        boolean zI = C1669Be.I(zT, c2743ve);
        boolean z4 = true;
        if (!zI && z2) {
            z4 = false;
        }
        InterfaceC1582a interfaceC1582a = zI ? null : c1669Be.e;
        C2614se c2614se = zT ? null : new C2614se(c2743ve, c1669Be.f);
        InterfaceC1999e9 interfaceC1999e9 = c1669Be.i;
        BinderC2408nm binderC2408nm = null;
        InterfaceC2043f9 interfaceC2043f9 = c1669Be.j;
        boolean z5 = z4;
        C2614se c2614se2 = c2614se;
        com.google.android.gms.ads.internal.overlay.c cVar = c1669Be.u;
        VersionInfoParcel versionInfoParcel = c2743ve.a.e;
        InterfaceC2447oi interfaceC2447oi = z5 ? null : c1669Be.k;
        if (C1669Be.E(c2743ve)) {
            binderC2408nm = c1669Be.F;
        }
        c1669Be.z0(new AdOverlayInfoParcel(interfaceC1582a, c2614se2, interfaceC1999e9, interfaceC2043f9, cVar, c2743ve, z, i, str, versionInfoParcel, interfaceC2447oi, binderC2408nm, z3));
    }

    public final synchronized String C0() {
        return this.z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void D(boolean z) {
        this.n.D = z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void D0() {
        setBackgroundColor(0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void E0(long j, boolean z) {
        HashMap map = new HashMap(2);
        map.put("success", true != z ? "0" : "1");
        map.put("duration", Long.toString(j));
        j("onCacheAccessComplete", map);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void F(Context context) {
        C1693Fe c1693Fe = this.a;
        c1693Fe.setBaseContext(context);
        this.c1.a = c1693Fe.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void F0(String str, InterfaceC2389n9 interfaceC2389n9) {
        C1669Be c1669Be = this.n;
        if (c1669Be != null) {
            synchronized (c1669Be.d) {
                try {
                    List list = (List) c1669Be.c.get(str);
                    if (list == null) {
                        return;
                    }
                    list.remove(interfaceC2389n9);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void G() {
        Qj qj = this.E;
        if (qj != null) {
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2104gj(qj, 1));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void G0(C2622sm c2622sm) {
        this.q = c2622sm;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized com.google.android.gms.ads.internal.overlay.d H() {
        return this.V;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized boolean H0() {
        return this.t;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void I0(boolean z) {
        try {
            boolean z2 = this.v;
            this.v = z;
            X();
            if (z != z2) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.W)).booleanValue()) {
                    if (!this.r.b()) {
                    }
                }
                try {
                    b("onStateChanged", new JSONObject().put("state", true != z ? "default" : "expanded"));
                } catch (JSONException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error occurred while dispatching state change.", e);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Context J() {
        return this.a.c;
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0051  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void K(java.lang.String r4) {
        /*
            r3 = this;
            monitor-enter(r3)
            java.lang.Boolean r0 = r3.x     // Catch: java.lang.Throwable -> L71
            monitor-exit(r3)
            r1 = 0
            if (r0 != 0) goto L30
            monitor-enter(r3)
            com.google.android.gms.ads.internal.j r0 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L22
            com.google.android.gms.internal.ads.ed r0 = r0.h     // Catch: java.lang.Throwable -> L22
            java.lang.Object r2 = r0.a     // Catch: java.lang.Throwable -> L22
            monitor-enter(r2)     // Catch: java.lang.Throwable -> L22
            java.lang.Boolean r0 = r0.i     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L2b
            r3.x = r0     // Catch: java.lang.Throwable -> L22
            if (r0 != 0) goto L20
            java.lang.String r0 = "(function(){})()"
            r3.evaluateJavascript(r0, r1)     // Catch: java.lang.Throwable -> L22 java.lang.IllegalStateException -> L24
            java.lang.Boolean r0 = java.lang.Boolean.TRUE     // Catch: java.lang.Throwable -> L22 java.lang.IllegalStateException -> L24
            r3.M(r0)     // Catch: java.lang.Throwable -> L22 java.lang.IllegalStateException -> L24
        L20:
            monitor-exit(r3)
            goto L30
        L22:
            r4 = move-exception
            goto L2e
        L24:
            java.lang.Boolean r0 = java.lang.Boolean.FALSE     // Catch: java.lang.Throwable -> L22
            r3.M(r0)     // Catch: java.lang.Throwable -> L22
            monitor-exit(r3)
            goto L30
        L2b:
            r4 = move-exception
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L2b
            throw r4     // Catch: java.lang.Throwable -> L22
        L2e:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L22
            throw r4
        L30:
            monitor-enter(r3)
            java.lang.Boolean r0 = r3.x     // Catch: java.lang.Throwable -> L6e
            monitor-exit(r3)
            boolean r0 = r0.booleanValue()
            if (r0 == 0) goto L51
            monitor-enter(r3)
            boolean r0 = r3.B()     // Catch: java.lang.Throwable -> L46
            if (r0 != 0) goto L48
            r3.evaluateJavascript(r4, r1)     // Catch: java.lang.Throwable -> L46
            monitor-exit(r3)
            goto L6b
        L46:
            r4 = move-exception
            goto L4f
        L48:
            java.lang.String r4 = "#004 The webview is destroyed. Ignoring action."
            com.google.android.gms.ads.internal.util.client.i.h(r4)     // Catch: java.lang.Throwable -> L46
            monitor-exit(r3)
            goto L6b
        L4f:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L46
            throw r4
        L51:
            java.lang.String r0 = "javascript:"
            java.lang.String r4 = r0.concat(r4)
            monitor-enter(r3)
            boolean r0 = r3.B()     // Catch: java.lang.Throwable -> L63
            if (r0 != 0) goto L65
            r3.loadUrl(r4)     // Catch: java.lang.Throwable -> L63
            monitor-exit(r3)
            goto L6b
        L63:
            r4 = move-exception
            goto L6c
        L65:
            java.lang.String r4 = "#004 The webview is destroyed. Ignoring action."
            com.google.android.gms.ads.internal.util.client.i.h(r4)     // Catch: java.lang.Throwable -> L63
            monitor-exit(r3)
        L6b:
            return
        L6c:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L63
            throw r4
        L6e:
            r4 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L6e
            throw r4
        L71:
            r4 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L71
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2829xe.K(java.lang.String):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void K0(zzc zzcVar, boolean z, boolean z2, String str) {
        this.n.r0(zzcVar, z, z2, str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final /* synthetic */ C1669Be L() {
        return this.n;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void L0(InterfaceC2517q8 interfaceC2517q8) {
        this.D = interfaceC2517q8;
    }

    public final void M(Boolean bool) {
        synchronized (this) {
            this.x = bool;
        }
        C2010ed c2010ed = com.google.android.gms.ads.internal.j.C.h;
        synchronized (c2010ed.a) {
            c2010ed.i = bool;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean M0() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final View N() {
        return this;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void N0(boolean z) {
        com.google.android.gms.ads.internal.overlay.d dVar;
        int i = this.G + (true != z ? -1 : 1);
        this.G = i;
        if (i > 0 || (dVar = this.o) == null) {
            return;
        }
        synchronized (dVar.n) {
            try {
                dVar.q = true;
                androidx.appcompat.app.J j = dVar.p;
                if (j != null) {
                    com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
                    b.removeCallbacks(j);
                    b.post(dVar.p);
                }
            } finally {
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized com.bumptech.glide.load.engine.cache.f O() {
        return this.r;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void O0(String str, InterfaceC2389n9 interfaceC2389n9) {
        C1669Be c1669Be = this.n;
        if (c1669Be != null) {
            c1669Be.a(str, interfaceC2389n9);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void P(String str, AbstractC1794Wd abstractC1794Wd) {
        try {
            if (this.i1 == null) {
                this.i1 = new HashMap();
            }
            this.i1.put(str, abstractC1794Wd);
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0043  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void P0() {
        /*
            r5 = this;
            java.util.HashMap r0 = new java.util.HashMap
            r1 = 3
            r0.<init>(r1)
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.a r3 = r2.i
            monitor-enter(r3)
            boolean r4 = r3.a     // Catch: java.lang.Throwable -> L53
            monitor-exit(r3)
            java.lang.String r3 = java.lang.String.valueOf(r4)
            java.lang.String r4 = "app_muted"
            r0.put(r4, r3)
            com.google.android.gms.ads.internal.util.a r2 = r2.i
            float r2 = r2.a()
            java.lang.String r2 = java.lang.String.valueOf(r2)
            java.lang.String r3 = "app_volume"
            r0.put(r3, r2)
            android.content.Context r2 = r5.getContext()
            java.lang.String r3 = "audio"
            java.lang.Object r2 = r2.getSystemService(r3)
            android.media.AudioManager r2 = (android.media.AudioManager) r2
            if (r2 != 0) goto L35
            goto L43
        L35:
            int r3 = r2.getStreamMaxVolume(r1)
            int r1 = r2.getStreamVolume(r1)
            if (r3 == 0) goto L43
            float r1 = (float) r1
            float r2 = (float) r3
            float r1 = r1 / r2
            goto L44
        L43:
            r1 = 0
        L44:
            java.lang.String r1 = java.lang.String.valueOf(r1)
            java.lang.String r2 = "device_volume"
            r0.put(r2, r1)
            java.lang.String r1 = "volume"
            r5.j(r1, r0)
            return
        L53:
            r0 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L53
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2829xe.P0():void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized com.google.android.gms.ads.internal.overlay.d Q() {
        return this.o;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void Q0(boolean z) {
        boolean z2;
        com.google.android.gms.ads.internal.overlay.d dVar = this.o;
        if (dVar == null) {
            this.t = z;
            return;
        }
        C1669Be c1669Be = this.n;
        synchronized (c1669Be.d) {
            z2 = c1669Be.q;
        }
        dVar.k4(z2, z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void R() {
        com.google.android.gms.ads.internal.overlay.d dVarQ = Q();
        if (dVarQ != null) {
            dVarQ.l.b = true;
        }
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        boolean z;
        synchronized (this) {
            z = d5.j;
            this.B = z;
        }
        m0(z);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x008d, code lost:
    
        if (r10.h1 != r9) goto L31;
     */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00af  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean S() {
        /*
            r10 = this;
            com.google.android.gms.internal.ads.Be r0 = r10.n
            java.lang.Object r1 = r0.d
            monitor-enter(r1)
            boolean r0 = r0.q     // Catch: java.lang.Throwable -> Lc9
            monitor-exit(r1)     // Catch: java.lang.Throwable -> Lc9
            r1 = 0
            if (r0 != 0) goto L13
            com.google.android.gms.internal.ads.Be r0 = r10.n
            boolean r0 = r0.o()
            if (r0 == 0) goto L90
        L13:
            com.google.android.gms.ads.internal.client.q r0 = com.google.android.gms.ads.internal.client.C1614q.f
            com.google.android.gms.ads.internal.util.client.c r0 = r0.a
            android.util.DisplayMetrics r0 = r10.h
            int r2 = r0.widthPixels
            float r2 = (float) r2
            float r3 = r0.density
            float r2 = r2 / r3
            int r4 = java.lang.Math.round(r2)
            int r2 = r0.heightPixels
            float r2 = (float) r2
            float r3 = r0.density
            float r2 = r2 / r3
            int r5 = java.lang.Math.round(r2)
            com.google.android.gms.internal.ads.Fe r2 = r10.a
            android.app.Activity r2 = r2.a
            r3 = 1
            if (r2 == 0) goto L59
            android.view.Window r6 = r2.getWindow()
            if (r6 != 0) goto L3b
            goto L59
        L3b:
            com.google.android.gms.ads.internal.j r6 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.F r6 = r6.c
            int[] r2 = com.google.android.gms.ads.internal.util.F.n(r2)
            r6 = r2[r1]
            float r6 = (float) r6
            float r7 = r0.density
            float r6 = r6 / r7
            int r6 = java.lang.Math.round(r6)
            r2 = r2[r3]
            float r2 = (float) r2
            float r7 = r0.density
            float r2 = r2 / r7
            int r2 = java.lang.Math.round(r2)
            r7 = r2
            goto L5b
        L59:
            r6 = r4
            r7 = r5
        L5b:
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.F r2 = r2.c
            android.view.WindowManager r2 = r10.j1
            android.view.Display r2 = r2.getDefaultDisplay()
            int r9 = r2.getRotation()
            int r2 = r10.e1
            if (r2 != r4) goto L91
            int r2 = r10.d1
            if (r2 != r5) goto L91
            int r2 = r10.f1
            if (r2 != r6) goto L91
            int r2 = r10.g1
            if (r2 != r7) goto L91
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.Y
            com.google.android.gms.ads.internal.client.r r8 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r8 = r8.c
            java.lang.Object r2 = r8.a(r2)
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r2 == 0) goto L90
            int r2 = r10.h1
            if (r2 == r9) goto L90
            goto L91
        L90:
            return r1
        L91:
            int r2 = r10.e1
            if (r2 != r4) goto Laf
            int r2 = r10.d1
            if (r2 != r5) goto Laf
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.Y
            com.google.android.gms.ads.internal.client.r r8 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r8 = r8.c
            java.lang.Object r2 = r8.a(r2)
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r2 == 0) goto Lb0
            int r2 = r10.h1
            if (r2 == r9) goto Lb0
        Laf:
            r1 = r3
        Lb0:
            r10.e1 = r4
            r10.d1 = r5
            r10.f1 = r6
            r10.g1 = r7
            r10.h1 = r9
            com.google.android.gms.internal.ads.Fi r3 = new com.google.android.gms.internal.ads.Fi
            java.lang.String r2 = ""
            r8 = 9
            r3.<init>(r8, r10, r2)
            float r8 = r0.density
            r3.y(r4, r5, r6, r7, r8, r9)
            return r1
        Lc9:
            r0 = move-exception
            monitor-exit(r1)     // Catch: java.lang.Throwable -> Lc9
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2829xe.S():boolean");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized boolean S0() {
        return this.y;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized boolean T() {
        return this.v;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void U() {
        com.google.android.gms.ads.internal.util.A.l("Cannot add text view to inner AdWebView");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void V(String str, C2881yn c2881yn) {
        C1669Be c1669Be = this.n;
        if (c1669Be != null) {
            synchronized (c1669Be.d) {
                try {
                    List<InterfaceC2389n9> list = (List) c1669Be.c.get(str);
                    if (list == null) {
                        return;
                    }
                    ArrayList arrayList = new ArrayList();
                    for (InterfaceC2389n9 interfaceC2389n9 : list) {
                        if ((interfaceC2389n9 instanceof U9) && ((U9) interfaceC2389n9).a.equals((InterfaceC2389n9) c2881yn.b)) {
                            arrayList.add(interfaceC2389n9);
                        }
                    }
                    list.removeAll(arrayList);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void W(T5 t5) {
        this.F = t5;
    }

    public final synchronized void X() {
        try {
            Vp vp = this.j;
            if (vp != null && vp.m0) {
                com.google.android.gms.ads.internal.util.client.i.d("Disabling hardware acceleration on an overlay.");
                synchronized (this) {
                    try {
                        if (!this.w) {
                            setLayerType(1, null);
                        }
                        this.w = true;
                    } finally {
                    }
                }
                return;
            }
            if (this.v || this.r.b()) {
                com.google.android.gms.ads.internal.util.client.i.d("Enabling hardware acceleration on an overlay.");
                synchronized (this) {
                    try {
                        if (this.w) {
                            setLayerType(0, null);
                        }
                        this.w = false;
                    } finally {
                    }
                }
                return;
            }
            com.google.android.gms.ads.internal.util.client.i.d("Enabling hardware acceleration on an AdView.");
            synchronized (this) {
                try {
                    if (this.w) {
                        setLayerType(0, null);
                    }
                    this.w = false;
                } finally {
                }
            }
            return;
        } catch (Throwable th) {
            throw th;
        }
        throw th;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized InterfaceC2517q8 Y() {
        return this.D;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void Z(boolean z, int i, String str, String str2, boolean z2) {
        C1669Be c1669Be = this.n;
        C2743ve c2743ve = c1669Be.a;
        boolean zT = c2743ve.a.T();
        boolean zI = C1669Be.I(zT, c2743ve);
        boolean z3 = true;
        if (!zI && z2) {
            z3 = false;
        }
        InterfaceC1582a interfaceC1582a = zI ? null : c1669Be.e;
        C2614se c2614se = zT ? null : new C2614se(c2743ve, c1669Be.f);
        InterfaceC1999e9 interfaceC1999e9 = c1669Be.i;
        BinderC2408nm binderC2408nm = null;
        InterfaceC2043f9 interfaceC2043f9 = c1669Be.j;
        boolean z4 = z3;
        C2614se c2614se2 = c2614se;
        com.google.android.gms.ads.internal.overlay.c cVar = c1669Be.u;
        VersionInfoParcel versionInfoParcel = c2743ve.a.e;
        InterfaceC2447oi interfaceC2447oi = z4 ? null : c1669Be.k;
        if (C1669Be.E(c2743ve)) {
            binderC2408nm = c1669Be.F;
        }
        c1669Be.z0(new AdOverlayInfoParcel(interfaceC1582a, c2614se2, interfaceC1999e9, interfaceC2043f9, cVar, c2743ve, z, i, str, str2, versionInfoParcel, interfaceC2447oi, binderC2408nm));
    }

    @Override // com.google.android.gms.ads.internal.g
    public final synchronized void a() {
        C2881yn c2881yn = this.f;
        if (c2881yn != null) {
            c2881yn.a();
        }
    }

    public final synchronized void a0() {
        if (this.W) {
            return;
        }
        this.W = true;
        com.google.android.gms.ads.internal.j.C.h.j.decrementAndGet();
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final void b(String str, JSONObject jSONObject) {
        if (jSONObject == null) {
            jSONObject = new JSONObject();
        }
        StringBuilder sbH = AbstractC0147y.h("(window.AFMA_ReceiveMessage || function() {})('", str, "',", jSONObject.toString(), ");");
        com.google.android.gms.ads.internal.util.client.i.d("Dispatching AFMA event: ".concat(sbH.toString()));
        K(sbH.toString());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.google.common.util.concurrent.e b0() {
        J7 j7 = this.d;
        return j7 == null ? Tv.b : (Nv) AbstractC2025es.O(Nv.t(Tv.b), ((Long) V7.c.o()).longValue(), TimeUnit.MILLISECONDS, j7.c);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c() {
        C1669Be c1669Be = this.n;
        if (c1669Be != null) {
            c1669Be.c();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c0() {
        C1669Be c1669Be = this.n;
        if (c1669Be != null) {
            c1669Be.c0();
        }
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void d(String str, JSONObject jSONObject) {
        zzb(str, jSONObject.toString());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized C2622sm d0() {
        return this.q;
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void destroy() {
        com.google.android.datatransport.cct.internal.s sVarC;
        View decorView;
        try {
            C1732Mb c1732Mb = this.L;
            if (c1732Mb != null && (sVarC = com.google.android.gms.ads.internal.j.C.h.c()) != null) {
                ((ArrayBlockingQueue) sVarC.b).offer((B7) c1732Mb.c);
            }
            C0110t c0110t = this.c1;
            c0110t.e = false;
            Activity activity = (Activity) c0110t.a;
            if (activity != null && c0110t.c) {
                Window window = activity.getWindow();
                ViewTreeObserver viewTreeObserver = (window == null || (decorView = window.getDecorView()) == null) ? null : decorView.getViewTreeObserver();
                if (viewTreeObserver != null) {
                    viewTreeObserver.removeOnGlobalLayoutListener((ViewTreeObserverOnGlobalLayoutListenerC2829xe) c0110t.b);
                }
                c0110t.c = false;
            }
            com.google.android.gms.ads.internal.overlay.d dVar = this.o;
            if (dVar != null) {
                dVar.b();
                this.o.l();
                this.o = null;
            }
            this.p = null;
            this.q = null;
            this.n.S();
            this.F = null;
            this.f = null;
            setOnClickListener(null);
            setOnTouchListener(null);
            if (this.u) {
                return;
            }
            com.google.android.gms.ads.internal.j.C.A.a(this);
            z0();
            this.u = true;
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ma)).booleanValue()) {
                com.google.android.gms.ads.internal.util.A.l("Destroying the WebView immediately...");
                s();
                return;
            }
            Activity activity2 = this.a.a;
            if (activity2 != null && activity2.isDestroyed()) {
                com.google.android.gms.ads.internal.util.A.l("Destroying the WebView immediately...");
                s();
            } else {
                com.google.android.gms.ads.internal.util.A.l("Initiating WebView self destruct sequence in 3...");
                com.google.android.gms.ads.internal.util.A.l("Loading blank page in WebView, 2...");
                r0();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Vp e() {
        return this.j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void e0() {
        if (this.I == null) {
            C1732Mb c1732Mb = this.L;
            AbstractC2096gb.h((B7) c1732Mb.c, this.J, "aes2");
            C2902z7 c2902z7D = B7.d();
            this.I = c2902z7D;
            ((HashMap) c1732Mb.b).put("native:view_show", c2902z7D);
        }
        HashMap map = new HashMap(1);
        map.put("version", this.e.a);
        j("onshow", map);
    }

    @Override // android.webkit.WebView
    public final synchronized void evaluateJavascript(String str, ValueCallback valueCallback) {
        if (B()) {
            com.google.android.gms.ads.internal.util.client.i.j("#004 The webview is destroyed. Ignoring action.", null);
            if (valueCallback != null) {
                valueCallback.onReceiveValue(null);
                return;
            }
            return;
        }
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Na)).booleanValue() || Looper.getMainLooper().getThread() == Thread.currentThread()) {
            super.evaluateJavascript(str, valueCallback);
        } else {
            AbstractC2270kd.f.a(new C(this, str, valueCallback, 5));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized int f() {
        return this.M;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void f0(Vp vp, Xp xp) {
        this.j = vp;
        this.k = xp;
    }

    public final void finalize() throws Throwable {
        try {
            synchronized (this) {
                try {
                    if (!this.u) {
                        this.n.S();
                        com.google.android.gms.ads.internal.j.C.A.a(this);
                        z0();
                        a0();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        } finally {
            super.finalize();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final int g() {
        return getMeasuredWidth();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized C2665tm g0() {
        return this.p;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final int h() {
        return getMeasuredHeight();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final P4 h0() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final androidx.work.impl.model.c i() {
        return this.g;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Xp i0() {
        return this.k;
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final void j(String str, Map map) {
        try {
            b(str, C1614q.f.a.i(map));
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not convert parameters to JSON.");
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void j0(int i) {
        C2902z7 c2902z7 = this.J;
        C1732Mb c1732Mb = this.L;
        if (i == 0) {
            AbstractC2096gb.h((B7) c1732Mb.c, c2902z7, "aebb2");
        }
        AbstractC2096gb.h((B7) c1732Mb.c, c2902z7, "aeh2");
        c1732Mb.getClass();
        ((B7) c1732Mb.c).b("close_type", String.valueOf(i));
        HashMap map = new HashMap(2);
        map.put("closetype", String.valueOf(i));
        map.put("version", this.e.a);
        j("onhide", map);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C1732Mb k() {
        return this.L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void k0(com.bumptech.glide.load.engine.cache.f fVar) {
        this.r = fVar;
        requestLayout();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final VersionInfoParcel l() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized boolean l0() {
        return this.G > 0;
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void loadData(String str, String str2, String str3) {
        if (B()) {
            com.google.android.gms.ads.internal.util.client.i.h("#004 The webview is destroyed. Ignoring action.");
        } else {
            super.loadData(str, str2, str3);
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void loadDataWithBaseURL(String str, String str2, String str3, String str4, String str5) throws Throwable {
        try {
            try {
                if (B()) {
                    com.google.android.gms.ads.internal.util.client.i.h("#004 The webview is destroyed. Ignoring action.");
                } else {
                    super.loadDataWithBaseURL(str, str2, str3, str4, str5);
                }
            } catch (Throwable th) {
                th = th;
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            throw th;
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void loadUrl(String str) {
        if (B()) {
            com.google.android.gms.ads.internal.util.client.i.h("#004 The webview is destroyed. Ignoring action.");
            return;
        }
        try {
            com.google.android.gms.ads.internal.util.F.l.post(new Qv(17, this, str));
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.h("AdWebViewImpl.loadUrl", th);
            com.google.android.gms.ads.internal.util.client.i.i("Could not call loadUrl. ", th);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.quizlet.remote.model.notes.e m() {
        return null;
    }

    public final void m0(boolean z) {
        HashMap map = new HashMap();
        map.put("isVisible", true != z ? "0" : "1");
        j("onAdVisibilityChanged", map);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final WebView n() {
        return this;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void n0() {
        this.l1 = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized String o0() {
        return this.s;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        C1669Be c1669Be = this.n;
        if (c1669Be != null) {
            c1669Be.onAdClicked();
        }
    }

    @Override // android.webkit.WebView, android.view.ViewGroup, android.view.View
    public final synchronized void onAttachedToWindow() {
        try {
            super.onAttachedToWindow();
            boolean z = true;
            if (!B()) {
                C0110t c0110t = this.c1;
                c0110t.d = true;
                if (c0110t.e) {
                    c0110t.d();
                }
            }
            if (this.l1) {
                onResume();
                this.l1 = false;
            }
            boolean z2 = this.B;
            C1669Be c1669Be = this.n;
            if (c1669Be == null || !c1669Be.o()) {
                z = z2;
            } else {
                if (!this.C) {
                    synchronized (this.n.d) {
                    }
                    synchronized (this.n.d) {
                    }
                    this.C = true;
                }
                S();
            }
            m0(z);
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        C1669Be c1669Be;
        View decorView;
        synchronized (this) {
            try {
                if (!B()) {
                    C0110t c0110t = this.c1;
                    c0110t.d = false;
                    Activity activity = (Activity) c0110t.a;
                    if (activity != null && c0110t.c) {
                        Window window = activity.getWindow();
                        ViewTreeObserver viewTreeObserver = (window == null || (decorView = window.getDecorView()) == null) ? null : decorView.getViewTreeObserver();
                        if (viewTreeObserver != null) {
                            viewTreeObserver.removeOnGlobalLayoutListener((ViewTreeObserverOnGlobalLayoutListenerC2829xe) c0110t.b);
                        }
                        c0110t.c = false;
                    }
                }
                super.onDetachedFromWindow();
                if (this.C && (c1669Be = this.n) != null && c1669Be.o() && getViewTreeObserver() != null && getViewTreeObserver().isAlive()) {
                    synchronized (this.n.d) {
                    }
                    synchronized (this.n.d) {
                    }
                    this.C = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        m0(false);
    }

    @Override // android.webkit.DownloadListener
    public final void onDownloadStart(String str, String str2, String str3, String str4, long j) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setDataAndType(Uri.parse(str), str4);
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.bb)).booleanValue() && getContext() != null) {
                intent.setPackage(getContext().getPackageName());
            }
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            com.google.android.gms.ads.internal.util.F.q(getContext(), intent);
        } catch (ActivityNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.i.d("Couldn't find an Activity to view url/mimetype: " + str + " / " + str4);
            com.google.android.gms.ads.internal.j.C.h.h("AdWebViewImpl.onDownloadStart: ".concat(String.valueOf(str)), e);
        }
    }

    @Override // android.webkit.WebView, android.view.View
    public final void onDraw(Canvas canvas) {
        if (B()) {
            return;
        }
        super.onDraw(canvas);
    }

    @Override // android.webkit.WebView, android.view.View
    public final boolean onGenericMotionEvent(MotionEvent motionEvent) {
        float axisValue = motionEvent.getAxisValue(9);
        float axisValue2 = motionEvent.getAxisValue(10);
        if (motionEvent.getActionMasked() == 8) {
            if (axisValue > DefinitionKt.NO_Float_VALUE && !canScrollVertically(-1)) {
                return false;
            }
            if (axisValue < DefinitionKt.NO_Float_VALUE && !canScrollVertically(1)) {
                return false;
            }
            if (axisValue2 > DefinitionKt.NO_Float_VALUE && !canScrollHorizontally(-1)) {
                return false;
            }
            if (axisValue2 < DefinitionKt.NO_Float_VALUE && !canScrollHorizontally(1)) {
                return false;
            }
        }
        return super.onGenericMotionEvent(motionEvent);
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        boolean zS = S();
        com.google.android.gms.ads.internal.overlay.d dVarQ = Q();
        if (dVarQ != null && zS && dVarQ.m) {
            dVarQ.m = false;
            dVarQ.d.e0();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0083  */
    @Override // android.webkit.WebView, android.widget.AbsoluteLayout, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void onMeasure(int r11, int r12) {
        /*
            Method dump skipped, instructions count: 464
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2829xe.onMeasure(int, int):void");
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void onPause() {
        if (B()) {
            return;
        }
        try {
            super.onPause();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ac)).booleanValue() && AbstractC3379p2.c("MUTE_AUDIO")) {
                com.google.android.gms.ads.internal.util.client.i.d("Muting webview");
                int i = androidx.webkit.i.a;
                if (!androidx.webkit.internal.s.g.b()) {
                    throw androidx.webkit.internal.s.a();
                }
                ((WebViewProviderBoundaryInterface) androidx.webkit.i.b(this).b).setAudioMuted(true);
            }
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("Could not pause webview.", e);
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Dc)).booleanValue()) {
                com.google.android.gms.ads.internal.j.C.h.h("AdWebViewImpl.onPause", e);
            }
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void onResume() {
        if (B()) {
            return;
        }
        try {
            super.onResume();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ac)).booleanValue() && AbstractC3379p2.c("MUTE_AUDIO")) {
                com.google.android.gms.ads.internal.util.client.i.d("Unmuting webview");
                int i = androidx.webkit.i.a;
                if (!androidx.webkit.internal.s.g.b()) {
                    throw androidx.webkit.internal.s.a();
                }
                ((WebViewProviderBoundaryInterface) androidx.webkit.i.b(this).b).setAudioMuted(false);
            }
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("Could not resume webview.", e);
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Dc)).booleanValue()) {
                com.google.android.gms.ads.internal.j.C.h.h("AdWebViewImpl.onResume", e);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0020  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x003e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // android.webkit.WebView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onTouchEvent(android.view.MotionEvent r8) {
        /*
            r7 = this;
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.E3
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r1 = r1.c
            java.lang.Object r0 = r1.a(r0)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            r1 = 1
            r2 = 0
            if (r0 == 0) goto L20
            com.google.android.gms.internal.ads.Be r0 = r7.n
            java.lang.Object r3 = r0.d
            monitor-enter(r3)
            boolean r0 = r0.s     // Catch: java.lang.Throwable -> L22
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L22
            if (r0 == 0) goto L20
            r0 = r1
            goto L25
        L20:
            r0 = r2
            goto L25
        L22:
            r8 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L22
            throw r8
        L25:
            com.google.android.gms.internal.ads.Be r3 = r7.n
            boolean r3 = r3.o()
            if (r3 == 0) goto L3b
            com.google.android.gms.internal.ads.Be r3 = r7.n
            java.lang.Object r4 = r3.d
            monitor-enter(r4)
            boolean r3 = r3.t     // Catch: java.lang.Throwable -> L38
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L38
            if (r3 == 0) goto L3d
            goto L3b
        L38:
            r8 = move-exception
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L38
            throw r8
        L3b:
            if (r0 == 0) goto L4c
        L3d:
            monitor-enter(r7)
            com.google.android.gms.internal.ads.q8 r0 = r7.D     // Catch: java.lang.Throwable -> L46
            if (r0 == 0) goto L48
            r0.g(r8)     // Catch: java.lang.Throwable -> L46
            goto L48
        L46:
            r8 = move-exception
            goto L4a
        L48:
            monitor-exit(r7)     // Catch: java.lang.Throwable -> L46
            goto L8f
        L4a:
            monitor-exit(r7)     // Catch: java.lang.Throwable -> L46
            throw r8
        L4c:
            com.google.android.gms.internal.ads.P4 r0 = r7.b
            if (r0 == 0) goto L55
            com.google.android.gms.internal.ads.N4 r0 = r0.b
            r0.h(r8)
        L55:
            com.google.android.gms.internal.ads.J7 r0 = r7.d
            if (r0 == 0) goto L8f
            int r3 = r8.getAction()
            if (r3 != r1) goto L75
            long r3 = r8.getEventTime()
            android.view.MotionEvent r1 = r0.a
            long r5 = r1.getEventTime()
            int r1 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r1 > 0) goto L6e
            goto L75
        L6e:
            android.view.MotionEvent r1 = android.view.MotionEvent.obtain(r8)
            r0.a = r1
            goto L8f
        L75:
            int r1 = r8.getAction()
            if (r1 != 0) goto L8f
            long r3 = r8.getEventTime()
            android.view.MotionEvent r1 = r0.b
            long r5 = r1.getEventTime()
            int r1 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r1 <= 0) goto L8f
            android.view.MotionEvent r1 = android.view.MotionEvent.obtain(r8)
            r0.b = r1
        L8f:
            boolean r0 = r7.B()
            if (r0 == 0) goto L96
            return r2
        L96:
            boolean r8 = super.onTouchEvent(r8)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2829xe.onTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized BinderC2915ze p() {
        return this.A;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void p0(Qj qj) {
        this.E = qj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void q0(int i) {
        this.M = i;
    }

    @Override // com.google.android.gms.ads.internal.g
    public final synchronized void r() {
        C2881yn c2881yn = this.f;
        if (c2881yn != null) {
            c2881yn.r();
        }
    }

    public final synchronized void r0() {
        try {
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2700ue(this, 1));
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.h("AdWebViewImpl.loadUrlUnsafe", th);
            com.google.android.gms.ads.internal.util.client.i.i("Could not call loadUrl in destroy(). ", th);
        }
    }

    public final synchronized void s() {
        com.google.android.gms.ads.internal.util.A.l("Destroying WebView!");
        a0();
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2700ue(this, 2));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void s0(com.google.android.gms.ads.internal.overlay.d dVar) {
        this.V = dVar;
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void setWebViewClient(WebViewClient webViewClient) {
        super.setWebViewClient(webViewClient);
        if (webViewClient instanceof C1669Be) {
            this.n = (C1669Be) webViewClient;
        }
    }

    @Override // android.webkit.WebView
    public final void stopLoading() {
        if (B()) {
            return;
        }
        try {
            super.stopLoading();
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("Could not stop loading webview.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void t(int i) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void t0(String str, String str2) {
        C1669Be c1669Be = this.n;
        c1669Be.getClass();
        C2743ve c2743ve = c1669Be.a;
        c1669Be.z0(new AdOverlayInfoParcel(c2743ve, c2743ve.a.e, str, str2, c1669Be.F));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void u(com.google.android.gms.ads.internal.overlay.d dVar) {
        this.o = dVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final ArrayList u0() {
        return new ArrayList();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void v0(BinderC2915ze binderC2915ze) {
        if (this.A != null) {
            com.google.android.gms.ads.internal.util.client.i.e("Attempt to create multiple AdWebViewVideoControllers.");
        } else {
            this.A = binderC2915ze;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized String w() {
        Xp xp = this.k;
        if (xp == null) {
            return null;
        }
        return xp.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void w0(String str, String str2) throws Throwable {
        Throwable th;
        String str3;
        try {
            try {
                if (B()) {
                    com.google.android.gms.ads.internal.util.client.i.h("#004 The webview is destroyed. Ignoring action.");
                    return;
                }
                String str4 = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.V);
                JSONObject jSONObject = new JSONObject();
                try {
                    try {
                        jSONObject.put("version", str4);
                        jSONObject.put("sdk", "Google Mobile Ads");
                        jSONObject.put("sdkVersion", "12.4.51-000");
                        str3 = "<script>Object.defineProperty(window,'MRAID_ENV',{get:function(){return " + jSONObject.toString() + "}});</script>";
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                } catch (JSONException e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Unable to build MRAID_ENV", e);
                    str3 = null;
                }
                super.loadDataWithBaseURL(str, AbstractC1675Ce.b(str2, str3), "text/html", "UTF-8", null);
            } catch (Throwable th3) {
                th = th3;
                th = th;
                throw th;
            }
        } catch (Throwable th4) {
            th = th4;
            th = th;
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void x(boolean z) {
        this.y = z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void x0(boolean z) {
        if (z) {
            try {
                setBackgroundColor(0);
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.ads.internal.overlay.d dVar = this.o;
        if (dVar != null) {
            if (z) {
                dVar.l.setBackgroundColor(0);
            } else {
                dVar.l.setBackgroundColor(-16777216);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void y(int i, boolean z, boolean z2) {
        InterfaceC1582a interfaceC1582a;
        InterfaceC2447oi interfaceC2447oi;
        BinderC2408nm binderC2408nm;
        int i2;
        InterfaceC1582a interfaceC1582a2;
        boolean z3;
        C1669Be c1669Be = this.n;
        C2743ve c2743ve = c1669Be.a;
        boolean zI = C1669Be.I(c2743ve.a.T(), c2743ve);
        boolean z4 = true;
        if (!zI && z2) {
            z4 = false;
        }
        if (zI) {
            interfaceC1582a = null;
            interfaceC2447oi = null;
        } else {
            interfaceC1582a = c1669Be.e;
            interfaceC2447oi = null;
        }
        com.google.android.gms.ads.internal.overlay.j jVar = c1669Be.f;
        InterfaceC2447oi interfaceC2447oi2 = interfaceC2447oi;
        com.google.android.gms.ads.internal.overlay.c cVar = c1669Be.u;
        VersionInfoParcel versionInfoParcel = c2743ve.a.e;
        InterfaceC2447oi interfaceC2447oi3 = z4 ? interfaceC2447oi2 : c1669Be.k;
        if (C1669Be.E(c2743ve)) {
            binderC2408nm = c1669Be.F;
            i2 = i;
            z3 = z;
            interfaceC1582a2 = interfaceC1582a;
        } else {
            binderC2408nm = interfaceC2447oi2;
            i2 = i;
            interfaceC1582a2 = interfaceC1582a;
            z3 = z;
        }
        c1669Be.z0(new AdOverlayInfoParcel(interfaceC1582a2, jVar, cVar, c2743ve, z3, i2, versionInfoParcel, interfaceC2447oi3, binderC2408nm));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized T5 y0() {
        return this.F;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final synchronized void z(int i) {
        com.google.android.gms.ads.internal.overlay.d dVar = this.o;
        if (dVar != null) {
            dVar.e4(i);
        }
    }

    public final synchronized void z0() {
        try {
            HashMap map = this.i1;
            if (map != null) {
                Iterator it2 = map.values().iterator();
                while (it2.hasNext()) {
                    ((AbstractC1794Wd) it2.next()).j();
                }
            }
            this.i1 = null;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void zza(String str) {
        K(str);
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void zzb(String str, String str2) {
        K(str + "(" + str2 + ");");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Activity zzi() {
        return this.a.a;
    }
}
