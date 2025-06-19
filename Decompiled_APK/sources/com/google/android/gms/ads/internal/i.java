package com.google.android.gms.ads.internal;

import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.ViewGroup;
import android.webkit.WebView;
import androidx.appcompat.widget.F0;
import androidx.camera.camera2.internal.c0;
import com.amazon.device.ads.DtbConstants;
import com.facebook.internal.L;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.internal.client.A;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.InterfaceC1619u;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.J;
import com.google.android.gms.ads.internal.client.P;
import com.google.android.gms.ads.internal.client.T;
import com.google.android.gms.ads.internal.client.V;
import com.google.android.gms.ads.internal.client.s0;
import com.google.android.gms.ads.internal.client.v0;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzr;
import com.google.android.gms.ads.internal.client.zzx;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.C2097gc;
import com.google.android.gms.internal.ads.D7;
import com.google.android.gms.internal.ads.InterfaceC1866b6;
import com.google.android.gms.internal.ads.L7;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.mlkit_vision_common.U2;
import java.util.Iterator;
import java.util.TreeMap;

/* loaded from: classes2.dex */
public final class i extends J {
    public final VersionInfoParcel a;
    public final zzr b;
    public final com.google.common.util.concurrent.e c = AbstractC2270kd.a.d(new androidx.camera.core.impl.utils.executor.c(this, 7));
    public final Context d;
    public final c0 e;
    public WebView f;
    public InterfaceC1622x g;
    public P4 h;
    public AsyncTask i;

    public i(Context context, zzr zzrVar, String str, VersionInfoParcel versionInfoParcel) {
        this.d = context;
        this.a = versionInfoParcel;
        this.b = zzrVar;
        this.f = new WebView(context);
        this.e = new c0(context, str);
        e4(0);
        this.f.setVerticalScrollBarEnabled(false);
        this.f.getSettings().setJavaScriptEnabled(true);
        this.f.setWebViewClient(new L(this, 1));
        this.f.setOnTouchListener(new F0(this, 1));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A0(P p) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A1(zzr zzrVar) {
        throw new IllegalStateException("AdSize must be set before initialization");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A3(InterfaceC1619u interfaceC1619u) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void E1(C2097gc c2097gc) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean F3() {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void H() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean I2(zzm zzmVar) {
        TreeMap treeMap;
        u.i(this.f, "This Search Ad has already been torn down");
        c0 c0Var = this.e;
        c0Var.getClass();
        c0Var.e = zzmVar.j.a;
        Bundle bundle = zzmVar.m;
        Bundle bundle2 = bundle != null ? bundle.getBundle(AdMobAdapter.class.getName()) : null;
        if (bundle2 != null) {
            String str = (String) L7.c.o();
            Iterator<String> it2 = bundle2.keySet().iterator();
            while (true) {
                boolean zHasNext = it2.hasNext();
                treeMap = (TreeMap) c0Var.d;
                if (!zHasNext) {
                    break;
                }
                String next = it2.next();
                if (str.equals(next)) {
                    c0Var.f = bundle2.getString(next);
                } else if (next.startsWith("csa_")) {
                    treeMap.put(next.substring(4), bundle2.getString(next));
                }
            }
            treeMap.put("SDKVersion", this.a.a);
            if (((Boolean) L7.a.o()).booleanValue()) {
                Bundle bundleD = U2.d((Context) c0Var.b, (String) L7.b.o());
                for (String str2 : bundleD.keySet()) {
                    treeMap.put(str2, bundleD.get(str2).toString());
                }
            }
        }
        this.i = new h(this).execute(new Void[0]);
        return true;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void J() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void K() {
        u.d("resume must be called on the main UI thread.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void M0(V v) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void N1(InterfaceC1622x interfaceC1622x) {
        this.g = interfaceC1622x;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void O1(T t) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void P() {
        u.d("pause must be called on the main UI thread.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void W1(zzfw zzfwVar) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void X3(boolean z) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y0(zzm zzmVar, A a) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void b0() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void c3(boolean z) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean e0() {
        return false;
    }

    public final void e4(int i) {
        if (this.f == null) {
            return;
        }
        this.f.setLayoutParams(new ViewGroup.LayoutParams(-1, i));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void f1() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g0() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g3(InterfaceC1866b6 interfaceC1866b6) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final zzr h() {
        return this.b;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final P i() {
        throw new IllegalStateException("getIAppEventListener not implemented");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void i0() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final Bundle j() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j0() {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j3(InterfaceC1609n0 interfaceC1609n0) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final v0 k() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void k1(zzx zzxVar) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.dynamic.a m() {
        u.d("getAdFrame must be called on the main UI thread.");
        return new com.google.android.gms.dynamic.b(this.f);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final s0 n() {
        return null;
    }

    public final String p() {
        String str = (String) this.e.f;
        if (true == TextUtils.isEmpty(str)) {
            str = "www.google.com";
        }
        return android.support.v4.media.session.a.B(DtbConstants.HTTPS, str, (String) L7.d.o());
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void p1(D7 d7) {
        throw new IllegalStateException("Unused method");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String s() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void s1(com.google.android.gms.dynamic.a aVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean t3() {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String w() {
        throw new IllegalStateException("getAdUnitId not implemented");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void y() {
        u.d("destroy must be called on the main UI thread.");
        this.i.cancel(true);
        this.c.cancel(false);
        this.f.destroy();
        this.f = null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String z() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final InterfaceC1622x zzi() {
        throw new IllegalStateException("getIAdListener not implemented");
    }
}
