package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.qe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public interface InterfaceC2529qe extends InterfaceC1582a, InterfaceC2447oi, R9, W9, E5, com.google.android.gms.ads.internal.g {
    C2067fq A0();

    boolean B();

    void B0(C2665tm c2665tm);

    void C(boolean z, int i, String str, boolean z2, boolean z3);

    void D(boolean z);

    void D0();

    void E0(long j, boolean z);

    void F(Context context);

    void F0(String str, InterfaceC2389n9 interfaceC2389n9);

    void G();

    void G0(C2622sm c2622sm);

    com.google.android.gms.ads.internal.overlay.d H();

    boolean H0();

    void I0(boolean z);

    Context J();

    void K0(zzc zzcVar, boolean z, boolean z2, String str);

    C1669Be L();

    void L0(InterfaceC2517q8 interfaceC2517q8);

    boolean M0();

    View N();

    void N0(boolean z);

    com.bumptech.glide.load.engine.cache.f O();

    void O0(String str, InterfaceC2389n9 interfaceC2389n9);

    void P(String str, AbstractC1794Wd abstractC1794Wd);

    void P0();

    com.google.android.gms.ads.internal.overlay.d Q();

    void Q0(boolean z);

    void R();

    boolean S0();

    boolean T();

    void U();

    void V(String str, C2881yn c2881yn);

    void W(T5 t5);

    InterfaceC2517q8 Y();

    void Z(boolean z, int i, String str, String str2, boolean z2);

    com.google.common.util.concurrent.e b0();

    boolean canGoBack();

    C2622sm d0();

    void destroy();

    Vp e();

    void e0();

    int f();

    void f0(Vp vp, Xp xp);

    int g();

    C2665tm g0();

    Context getContext();

    ViewGroup.LayoutParams getLayoutParams();

    ViewParent getParent();

    int getWidth();

    void goBack();

    int h();

    P4 h0();

    androidx.work.impl.model.c i();

    Xp i0();

    boolean isAttachedToWindow();

    void j0(int i);

    C1732Mb k();

    void k0(com.bumptech.glide.load.engine.cache.f fVar);

    VersionInfoParcel l();

    boolean l0();

    void loadData(String str, String str2, String str3);

    void loadDataWithBaseURL(String str, String str2, String str3, String str4, String str5);

    void loadUrl(String str);

    com.quizlet.remote.model.notes.e m();

    WebView n();

    void n0();

    String o0();

    void onPause();

    void onResume();

    BinderC2915ze p();

    void p0(Qj qj);

    void q0(int i);

    void s0(com.google.android.gms.ads.internal.overlay.d dVar);

    void setBackgroundColor(int i);

    void setOnClickListener(View.OnClickListener onClickListener);

    void setOnTouchListener(View.OnTouchListener onTouchListener);

    void setWebChromeClient(WebChromeClient webChromeClient);

    void setWebViewClient(WebViewClient webViewClient);

    void t(int i);

    void t0(String str, String str2);

    void u(com.google.android.gms.ads.internal.overlay.d dVar);

    ArrayList u0();

    void v0(BinderC2915ze binderC2915ze);

    String w();

    void w0(String str, String str2);

    void x(boolean z);

    void x0(boolean z);

    void y(int i, boolean z, boolean z2);

    T5 y0();

    void z(int i);

    Activity zzi();
}
