package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.GradientDrawable;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ve, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2743ve extends FrameLayout implements InterfaceC2529qe {
    public final ViewTreeObserverOnGlobalLayoutListenerC2829xe a;
    public final com.quizlet.remote.model.notes.e b;
    public final AtomicBoolean c;

    public C2743ve(ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe, Hk hk) {
        super(viewTreeObserverOnGlobalLayoutListenerC2829xe.getContext());
        this.c = new AtomicBoolean();
        this.a = viewTreeObserverOnGlobalLayoutListenerC2829xe;
        this.b = new com.quizlet.remote.model.notes.e(viewTreeObserverOnGlobalLayoutListenerC2829xe.a.c, this, this, hk);
        addView(viewTreeObserverOnGlobalLayoutListenerC2829xe);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C2067fq A0() {
        return this.a.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean B() {
        return this.a.B();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void B0(C2665tm c2665tm) {
        this.a.B0(c2665tm);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void C(boolean z, int i, String str, boolean z2, boolean z3) {
        this.a.C(z, i, str, z2, z3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void D(boolean z) {
        this.a.n.D = z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void D0() {
        setBackgroundColor(0);
        this.a.setBackgroundColor(0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void E0(long j, boolean z) {
        this.a.E0(j, z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void F(Context context) {
        this.a.F(context);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void F0(String str, InterfaceC2389n9 interfaceC2389n9) {
        this.a.F0(str, interfaceC2389n9);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void G() {
        this.a.G();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void G0(C2622sm c2622sm) {
        this.a.G0(c2622sm);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.google.android.gms.ads.internal.overlay.d H() {
        return this.a.H();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean H0() {
        return this.a.H0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void I0(boolean z) {
        this.a.I0(z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Context J() {
        return this.a.a.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void K0(zzc zzcVar, boolean z, boolean z2, String str) {
        this.a.K0(zzcVar, z, z2, str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C1669Be L() {
        return this.a.n;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void L0(InterfaceC2517q8 interfaceC2517q8) {
        this.a.L0(interfaceC2517q8);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean M0() {
        return this.c.get();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final View N() {
        return this;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void N0(boolean z) {
        this.a.N0(z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.bumptech.glide.load.engine.cache.f O() {
        return this.a.O();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void O0(String str, InterfaceC2389n9 interfaceC2389n9) {
        this.a.O0(str, interfaceC2389n9);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void P(String str, AbstractC1794Wd abstractC1794Wd) {
        this.a.P(str, abstractC1794Wd);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void P0() {
        this.a.P0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.google.android.gms.ads.internal.overlay.d Q() {
        return this.a.Q();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void Q0(boolean z) {
        this.a.Q0(z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void R() {
        this.a.R();
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        this.a.R0(d5);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean S0() {
        return this.a.S0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean T() {
        return this.a.T();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void U() {
        C2665tm c2665tmG0;
        C2622sm c2622smD0;
        TextView textView = new TextView(getContext());
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.F f = jVar.c;
        Resources resourcesB = jVar.h.b();
        textView.setText(resourcesB != null ? resourcesB.getString(R.string.s7) : "Test Ad");
        textView.setTextSize(15.0f);
        textView.setTextColor(-1);
        textView.setPadding(5, 0, 5, 0);
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setColor(-12303292);
        gradientDrawable.setCornerRadius(8.0f);
        textView.setBackground(gradientDrawable);
        addView(textView, new FrameLayout.LayoutParams(-2, -2, 49));
        bringChildToFront(textView);
        C2601s7 c2601s7 = AbstractC2773w7.n5;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        if (zBooleanValue && (c2622smD0 = viewTreeObserverOnGlobalLayoutListenerC2829xe.d0()) != null) {
            synchronized (c2622smD0) {
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = c2622smD0.f;
                if (gVar != null) {
                    jVar.x.getClass();
                    C2147hi.p(new RunnableC2793wl(2, gVar, textView));
                    return;
                }
                return;
            }
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.m5)).booleanValue() && (c2665tmG0 = viewTreeObserverOnGlobalLayoutListenerC2829xe.g0()) != null && ((Gr) c2665tmG0.b.g) == Gr.HTML) {
            C2147hi c2147hi = jVar.x;
            Hr hr = c2665tmG0.a;
            c2147hi.getClass();
            C2147hi.p(new RunnableC2451om(hr, textView, 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void V(String str, C2881yn c2881yn) {
        this.a.V(str, c2881yn);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void W(T5 t5) {
        this.a.W(t5);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final InterfaceC2517q8 Y() {
        return this.a.Y();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void Z(boolean z, int i, String str, String str2, boolean z2) {
        this.a.Z(z, i, str, str2, z2);
    }

    @Override // com.google.android.gms.ads.internal.g
    public final void a() {
        this.a.a();
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final void b(String str, JSONObject jSONObject) {
        this.a.b(str, jSONObject);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.google.common.util.concurrent.e b0() {
        return this.a.b0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c() {
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe != null) {
            viewTreeObserverOnGlobalLayoutListenerC2829xe.c();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final void c0() {
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe != null) {
            viewTreeObserverOnGlobalLayoutListenerC2829xe.c0();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean canGoBack() {
        return this.a.canGoBack();
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void d(String str, JSONObject jSONObject) {
        this.a.zzb(str, jSONObject.toString());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C2622sm d0() {
        return this.a.d0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void destroy() {
        C2622sm c2622smD0;
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        C2665tm c2665tmG0 = viewTreeObserverOnGlobalLayoutListenerC2829xe.g0();
        if (c2665tmG0 != null) {
            com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
            b.post(new RunnableC1989e(c2665tmG0, 21));
            b.postDelayed(new RunnableC2700ue(viewTreeObserverOnGlobalLayoutListenerC2829xe, 0), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.l5)).intValue());
        } else if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.n5)).booleanValue() || (c2622smD0 = viewTreeObserverOnGlobalLayoutListenerC2829xe.d0()) == null) {
            viewTreeObserverOnGlobalLayoutListenerC2829xe.destroy();
        } else {
            com.google.android.gms.ads.internal.util.F.l.post(new Qv(16, this, c2622smD0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Vp e() {
        return this.a.j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void e0() {
        this.a.e0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final int f() {
        return this.a.f();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void f0(Vp vp, Xp xp) {
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        viewTreeObserverOnGlobalLayoutListenerC2829xe.j = vp;
        viewTreeObserverOnGlobalLayoutListenerC2829xe.k = xp;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final int g() {
        return ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.X3)).booleanValue() ? this.a.getMeasuredWidth() : getMeasuredWidth();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C2665tm g0() {
        return this.a.g0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void goBack() {
        this.a.goBack();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final int h() {
        return ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.X3)).booleanValue() ? this.a.getMeasuredHeight() : getMeasuredHeight();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final P4 h0() {
        return this.a.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final androidx.work.impl.model.c i() {
        return this.a.g;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Xp i0() {
        return this.a.k;
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final void j(String str, Map map) {
        this.a.j(str, map);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void j0(int i) {
        this.a.j0(i);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final C1732Mb k() {
        return this.a.L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void k0(com.bumptech.glide.load.engine.cache.f fVar) {
        this.a.k0(fVar);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final VersionInfoParcel l() {
        return this.a.e;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final boolean l0() {
        return this.a.l0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void loadData(String str, String str2, String str3) {
        this.a.loadData(str, "text/html", str3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void loadDataWithBaseURL(String str, String str2, String str3, String str4, String str5) throws Throwable {
        this.a.loadDataWithBaseURL(str, str2, "text/html", "UTF-8", null);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void loadUrl(String str) {
        this.a.loadUrl(str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final com.quizlet.remote.model.notes.e m() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final WebView n() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void n0() {
        this.a.l1 = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final String o0() {
        return this.a.o0();
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = this.a;
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe != null) {
            viewTreeObserverOnGlobalLayoutListenerC2829xe.onAdClicked();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void onPause() {
        AbstractC2656td abstractC2656td;
        com.quizlet.remote.model.notes.e eVar = this.b;
        eVar.getClass();
        com.google.android.gms.common.internal.u.d("onPause must be called from the UI thread.");
        C2785wd c2785wd = (C2785wd) eVar.f;
        if (c2785wd != null && (abstractC2656td = c2785wd.g) != null) {
            abstractC2656td.t();
        }
        this.a.onPause();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void onResume() {
        this.a.onResume();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final BinderC2915ze p() {
        return this.a.p();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void p0(Qj qj) {
        this.a.p0(qj);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void q0(int i) {
        this.a.q0(i);
    }

    @Override // com.google.android.gms.ads.internal.g
    public final void r() {
        this.a.r();
    }

    public final void s() {
        com.quizlet.remote.model.notes.e eVar = this.b;
        eVar.getClass();
        com.google.android.gms.common.internal.u.d("onDestroy must be called from the UI thread.");
        C2785wd c2785wd = (C2785wd) eVar.f;
        if (c2785wd != null) {
            c2785wd.e.a();
            AbstractC2656td abstractC2656td = c2785wd.g;
            if (abstractC2656td != null) {
                abstractC2656td.y();
            }
            c2785wd.b();
            ((C2743ve) eVar.d).removeView((C2785wd) eVar.f);
            eVar.f = null;
        }
        this.a.s();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void s0(com.google.android.gms.ads.internal.overlay.d dVar) {
        this.a.s0(dVar);
    }

    @Override // android.view.View, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void setOnClickListener(View.OnClickListener onClickListener) {
        this.a.setOnClickListener(onClickListener);
    }

    @Override // android.view.View, com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void setOnTouchListener(View.OnTouchListener onTouchListener) {
        this.a.setOnTouchListener(onTouchListener);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void setWebChromeClient(WebChromeClient webChromeClient) {
        this.a.setWebChromeClient(webChromeClient);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void setWebViewClient(WebViewClient webViewClient) {
        this.a.setWebViewClient(webViewClient);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void t(int i) {
        C2785wd c2785wd = (C2785wd) this.b.f;
        if (c2785wd != null) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M)).booleanValue()) {
                c2785wd.b.setBackgroundColor(i);
                c2785wd.c.setBackgroundColor(i);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void t0(String str, String str2) {
        this.a.t0(str, str2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void u(com.google.android.gms.ads.internal.overlay.d dVar) {
        this.a.u(dVar);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final ArrayList u0() {
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < getChildCount(); i++) {
            View childAt = getChildAt(i);
            if (childAt != this.a) {
                arrayList.add(childAt);
            }
        }
        return arrayList;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void v0(BinderC2915ze binderC2915ze) {
        this.a.v0(binderC2915ze);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final String w() {
        return this.a.w();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void w0(String str, String str2) throws Throwable {
        this.a.w0(str, str2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void x(boolean z) {
        this.a.x(z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void x0(boolean z) {
        this.a.x0(z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void y(int i, boolean z, boolean z2) {
        this.a.y(i, z, z2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final T5 y0() {
        return this.a.y0();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final void z(int i) {
        this.a.z(i);
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void zza(String str) {
        this.a.K(str);
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void zzb(String str, String str2) {
        this.a.zzb("window.inspectorInfo", str2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2529qe
    public final Activity zzi() {
        return this.a.a.a;
    }
}
