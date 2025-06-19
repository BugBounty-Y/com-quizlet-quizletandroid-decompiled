package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import android.webkit.WebView;
import androidx.collection.C0208f;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.gg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2101gg implements InterfaceC2617sh, InterfaceC2189ih {
    public final Context a;
    public final InterfaceC2529qe b;
    public final Vp c;
    public final VersionInfoParcel d;
    public C2665tm e;
    public boolean f;
    public final C2622sm g;

    public C2101gg(Context context, InterfaceC2529qe interfaceC2529qe, Vp vp, VersionInfoParcel versionInfoParcel, C2622sm c2622sm) {
        this.a = context;
        this.b = interfaceC2529qe;
        this.c = vp;
        this.d = versionInfoParcel;
        this.g = c2622sm;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final synchronized void K() {
        boolean z;
        InterfaceC2529qe interfaceC2529qe;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.n5)).booleanValue()) {
            C2622sm c2622sm = this.g;
            synchronized (c2622sm) {
                z = c2622sm.f != null;
            }
        }
        if (z) {
            this.g.a();
            return;
        }
        if (!this.f) {
            a();
        }
        if (!this.c.T || this.e == null || (interfaceC2529qe = this.b) == null) {
            return;
        }
        interfaceC2529qe.j("onSdkImpression", new C0208f(0));
    }

    public final synchronized void a() {
        InterfaceC2529qe interfaceC2529qe;
        int i;
        int i2;
        try {
            Vp vp = this.c;
            if (vp.T && (interfaceC2529qe = this.b) != null) {
                Context context = this.a;
                com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                jVar.x.getClass();
                if (C2147hi.l(context)) {
                    VersionInfoParcel versionInfoParcel = this.d;
                    String str = versionInfoParcel.b + "." + versionInfoParcel.c;
                    C2881yn c2881yn = vp.V;
                    String str2 = c2881yn.K() + (-1) != 1 ? "javascript" : null;
                    if (c2881yn.K() == 1) {
                        i = 2;
                        i2 = 3;
                    } else if (vp.e == 1) {
                        i = 3;
                        i2 = 1;
                    } else {
                        i = 1;
                        i2 = 1;
                    }
                    String str3 = vp.l0;
                    C2147hi c2147hi = jVar.x;
                    WebView webViewN = interfaceC2529qe.n();
                    c2147hi.getClass();
                    C2665tm c2665tmA = C2147hi.a(i, i2, webViewN, str, str2, str3);
                    this.e = c2665tmA;
                    if (c2665tmA != null) {
                        Hr hr = c2665tmA.a;
                        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.m5)).booleanValue()) {
                            C2147hi c2147hi2 = jVar.x;
                            WebView webViewN2 = interfaceC2529qe.n();
                            c2147hi2.getClass();
                            C2147hi.j(hr, webViewN2);
                            Iterator it2 = interfaceC2529qe.u0().iterator();
                            while (it2.hasNext()) {
                                View view = (View) it2.next();
                                com.google.android.gms.ads.internal.j.C.x.getClass();
                                C2147hi.p(new RunnableC2451om(hr, view, 0));
                            }
                        } else {
                            View viewN = interfaceC2529qe.N();
                            jVar.x.getClass();
                            C2147hi.j(hr, viewN);
                        }
                        interfaceC2529qe.B0(this.e);
                        com.google.android.gms.ads.internal.j.C.x.getClass();
                        C2147hi.k(hr);
                        this.f = true;
                        interfaceC2529qe.j("onSdkLoaded", new C0208f(0));
                    }
                }
            }
        } finally {
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final synchronized void s() {
        boolean z;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.n5)).booleanValue()) {
            C2622sm c2622sm = this.g;
            synchronized (c2622sm) {
                z = c2622sm.f != null;
            }
        }
        if (z) {
            this.g.b();
        } else {
            if (this.f) {
                return;
            }
            a();
        }
    }
}
