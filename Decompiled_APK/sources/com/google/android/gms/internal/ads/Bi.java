package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import android.webkit.WebView;
import androidx.collection.C0208f;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Bi implements InterfaceC2617sh, com.google.android.gms.ads.internal.overlay.j, InterfaceC2189ih {
    public final Context a;
    public final InterfaceC2529qe b;
    public final Vp c;
    public final VersionInfoParcel d;
    public final C2622sm e;
    public C2665tm f;

    public Bi(Context context, InterfaceC2529qe interfaceC2529qe, Vp vp, VersionInfoParcel versionInfoParcel, C2622sm c2622sm) {
        this.a = context;
        this.b = interfaceC2529qe;
        this.c = vp;
        this.d = versionInfoParcel;
        this.e = c2622sm;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
        InterfaceC2529qe interfaceC2529qe;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.q5)).booleanValue() || (interfaceC2529qe = this.b) == null) {
            return;
        }
        if (this.f != null || a()) {
            if (this.f != null) {
                interfaceC2529qe.j("onSdkImpression", new C0208f(0));
            } else {
                this.e.a();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        InterfaceC2529qe interfaceC2529qe;
        if (a()) {
            this.e.a();
        } else {
            if (this.f == null || (interfaceC2529qe = this.b) == null) {
                return;
            }
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.q5)).booleanValue()) {
                interfaceC2529qe.j("onSdkImpression", new C0208f(0));
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        this.f = null;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    public final boolean a() {
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.n5)).booleanValue()) {
            return false;
        }
        C2622sm c2622sm = this.e;
        synchronized (c2622sm) {
            gVar = c2622sm.f;
        }
        return gVar != null;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        InterfaceC2529qe interfaceC2529qe;
        Vp vp = this.c;
        if (!vp.T || (interfaceC2529qe = this.b) == null) {
            return;
        }
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        C2147hi c2147hi = jVar.x;
        Context context = this.a;
        c2147hi.getClass();
        if (C2147hi.l(context)) {
            if (a()) {
                this.e.b();
                return;
            }
            VersionInfoParcel versionInfoParcel = this.d;
            String str = versionInfoParcel.b + "." + versionInfoParcel.c;
            C2881yn c2881yn = vp.V;
            int i = 1;
            String str2 = c2881yn.K() + (-1) != 1 ? "javascript" : null;
            int i2 = 2;
            if (c2881yn.K() == 1) {
                i = 3;
            } else {
                i2 = vp.Y == 2 ? 4 : 1;
            }
            int i3 = i2;
            int i4 = i;
            WebView webViewN = interfaceC2529qe.n();
            C2147hi c2147hi2 = jVar.x;
            c2147hi2.getClass();
            C2665tm c2665tmA = C2147hi.a(i3, i4, webViewN, str, str2, vp.l0);
            this.f = c2665tmA;
            if (c2665tmA != null) {
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.m5)).booleanValue();
                Hr hr = c2665tmA.a;
                if (zBooleanValue) {
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
                    c2147hi2.getClass();
                    C2147hi.j(hr, viewN);
                }
                interfaceC2529qe.B0(this.f);
                com.google.android.gms.ads.internal.j.C.x.getClass();
                C2147hi.k(hr);
                interfaceC2529qe.j("onSdkLoaded", new C0208f(0));
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }
}
