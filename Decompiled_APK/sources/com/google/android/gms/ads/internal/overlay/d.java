package com.google.android.gms.ads.internal.overlay;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.RemoteException;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebChromeClient;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.RelativeLayout;
import android.widget.Toolbar;
import androidx.appcompat.app.J;
import androidx.appcompat.app.ViewOnClickListenerC0045a;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.ads.internal.zzl;
import com.google.android.gms.internal.ads.AbstractBinderC1666Bb;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2058fh;
import com.google.android.gms.internal.ads.C2063fm;
import com.google.android.gms.internal.ads.C2147hi;
import com.google.android.gms.internal.ads.C2210j2;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2622sm;
import com.google.android.gms.internal.ads.C2665tm;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Fk;
import com.google.android.gms.internal.ads.Gr;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.Hr;
import com.google.android.gms.internal.ads.InterfaceC2447oi;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.RunnableC2451om;
import com.google.android.gms.internal.ads.RunnableC2793wl;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import java.util.Collections;
import java.util.concurrent.ScheduledFuture;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d extends AbstractBinderC1666Bb {
    public static final int y = Color.argb(0, 0, 0, 0);
    public final Activity b;
    public AdOverlayInfoParcel c;
    public InterfaceC2529qe d;
    public com.google.android.gms.cloudmessaging.k e;
    public l f;
    public FrameLayout h;
    public WebChromeClient.CustomViewCallback i;
    public f l;
    public J p;
    public boolean q;
    public boolean r;
    public Toolbar v;
    public final /* synthetic */ int x;
    public boolean g = false;
    public boolean j = false;
    public boolean k = false;
    public boolean m = false;
    public int w = 1;
    public final Object n = new Object();
    public final ViewOnClickListenerC0045a o = new ViewOnClickListenerC0045a(this, 4);
    public boolean s = false;
    public boolean t = false;
    public boolean u = true;

    public d(int i, Activity activity) {
        this.x = i;
        this.b = activity;
    }

    public static final void i4(View view, C2665tm c2665tm) {
        if (c2665tm == null || view == null) {
            return;
        }
        if (((Boolean) r.d.c.a(AbstractC2773w7.m5)).booleanValue()) {
            C2210j2 c2210j2 = c2665tm.b;
            if (((Gr) c2210j2.g) == Gr.HTML) {
                return;
            }
        }
        C2147hi c2147hi = com.google.android.gms.ads.internal.j.C.x;
        Hr hr = c2665tm.a;
        c2147hi.getClass();
        C2147hi.j(hr, view);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void B2(Bundle bundle) {
        bundle.putBoolean("com.google.android.gms.ads.internal.overlay.hasResumed", this.j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void H1(int i, String[] strArr, int[] iArr) {
        if (i == 12345) {
            Activity activity = this.b;
            if (activity == null) {
                throw new NullPointerException("Null activity");
            }
            AdOverlayInfoParcel adOverlayInfoParcel = this.c;
            try {
                adOverlayInfoParcel.v.r1(strArr, iArr, new com.google.android.gms.dynamic.b(new C2063fm(activity, adOverlayInfoParcel.k == 5 ? this : null, null, null)));
            } catch (RemoteException unused) {
            }
        }
    }

    public final void N() {
        AdOverlayInfoParcel adOverlayInfoParcel;
        j jVar;
        if (!this.b.isFinishing() || this.s) {
            return;
        }
        this.s = true;
        InterfaceC2529qe interfaceC2529qe = this.d;
        if (interfaceC2529qe != null) {
            interfaceC2529qe.j0(this.w - 1);
            synchronized (this.n) {
                try {
                    if (!this.q && this.d.l0()) {
                        C2601s7 c2601s7 = AbstractC2773w7.Y4;
                        r rVar = r.d;
                        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && !this.t && (adOverlayInfoParcel = this.c) != null && (jVar = adOverlayInfoParcel.c) != null) {
                            jVar.f3();
                        }
                        J j = new J(this, 23);
                        this.p = j;
                        F.l.postDelayed(j, ((Long) rVar.c.a(AbstractC2773w7.b1)).longValue());
                        return;
                    }
                } finally {
                }
            }
        }
        q();
    }

    public final void b() {
        this.w = 3;
        Activity activity = this.b;
        activity.finish();
        AdOverlayInfoParcel adOverlayInfoParcel = this.c;
        if (adOverlayInfoParcel == null || adOverlayInfoParcel.k != 5) {
            return;
        }
        activity.overridePendingTransition(0, 0);
        InterfaceC2529qe interfaceC2529qe = this.d;
        if (interfaceC2529qe != null) {
            interfaceC2529qe.u(null);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void c() {
        if (((Boolean) r.d.c.a(AbstractC2773w7.a5)).booleanValue() && this.d != null && (!this.b.isFinishing() || this.e == null)) {
            this.d.onPause();
        }
        N();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void d() {
        j jVar;
        AdOverlayInfoParcel adOverlayInfoParcel = this.c;
        if (adOverlayInfoParcel == null || (jVar = adOverlayInfoParcel.c) == null) {
            return;
        }
        jVar.L2();
    }

    public final void e4(int i) {
        int i2;
        Activity activity = this.b;
        int i3 = activity.getApplicationInfo().targetSdkVersion;
        C2601s7 c2601s7 = AbstractC2773w7.V5;
        r rVar = r.d;
        if (i3 >= ((Integer) rVar.c.a(c2601s7)).intValue()) {
            int i4 = activity.getApplicationInfo().targetSdkVersion;
            C2601s7 c2601s72 = AbstractC2773w7.W5;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (i4 <= ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue() && (i2 = Build.VERSION.SDK_INT) >= ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.X5)).intValue() && i2 <= ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Y5)).intValue()) {
                return;
            }
        }
        try {
            activity.setRequestedOrientation(i);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.g("AdOverlay.setRequestedOrientation", th);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:19:0x002d  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0066  */
    /* JADX WARN: Type inference failed for: r0v23, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r0v37 */
    /* JADX WARN: Type inference failed for: r0v40 */
    /* JADX WARN: Type inference failed for: r0v41 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f4(boolean r41) throws org.json.JSONException, com.google.android.gms.ads.internal.overlay.e {
        /*
            Method dump skipped, instructions count: 713
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.overlay.d.f4(boolean):void");
    }

    public final void g4(View view) {
        C2665tm c2665tmG0;
        C2622sm c2622smD0;
        InterfaceC2529qe interfaceC2529qe = this.d;
        if (interfaceC2529qe == null) {
            return;
        }
        C2601s7 c2601s7 = AbstractC2773w7.n5;
        r rVar = r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && (c2622smD0 = interfaceC2529qe.d0()) != null) {
            synchronized (c2622smD0) {
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = c2622smD0.f;
                if (gVar != null) {
                    com.google.android.gms.ads.internal.j.C.x.getClass();
                    C2147hi.p(new RunnableC2793wl(2, gVar, view));
                    return;
                }
                return;
            }
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.m5)).booleanValue() && (c2665tmG0 = interfaceC2529qe.g0()) != null && ((Gr) c2665tmG0.b.g) == Gr.HTML) {
            C2147hi c2147hi = com.google.android.gms.ads.internal.j.C.x;
            Hr hr = c2665tmG0.a;
            c2147hi.getClass();
            C2147hi.p(new RunnableC2451om(hr, view, 0));
        }
    }

    public final void h() {
        AdOverlayInfoParcel adOverlayInfoParcel = this.c;
        if (adOverlayInfoParcel != null && this.g) {
            e4(adOverlayInfoParcel.j);
        }
        if (this.h != null) {
            this.b.setContentView(this.l);
            this.r = true;
            this.h.removeAllViews();
            this.h = null;
        }
        WebChromeClient.CustomViewCallback customViewCallback = this.i;
        if (customViewCallback != null) {
            customViewCallback.onCustomViewHidden();
            this.i = null;
        }
        this.g = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x002e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h4(android.content.res.Configuration r14) {
        /*
            Method dump skipped, instructions count: 318
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.overlay.d.h4(android.content.res.Configuration):void");
    }

    public final void j4(boolean z) throws JSONException {
        if (this.c.w) {
            return;
        }
        C2601s7 c2601s7 = AbstractC2773w7.d5;
        r rVar = r.d;
        int iIntValue = ((Integer) rVar.c.a(c2601s7)).intValue();
        boolean z2 = ((Boolean) rVar.c.a(AbstractC2773w7.e1)).booleanValue() || z;
        k kVar = new k();
        kVar.a = 0;
        kVar.b = 0;
        kVar.c = 0;
        kVar.d = 50;
        kVar.a = true != z2 ? 0 : iIntValue;
        kVar.b = true != z2 ? iIntValue : 0;
        kVar.c = iIntValue;
        this.f = new l(this.b, kVar, this);
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-2, -2);
        layoutParams.addRule(10);
        layoutParams.addRule(true != z2 ? 9 : 11);
        k4(z, this.c.g);
        this.l.addView(this.f, layoutParams);
        g4(this.f);
    }

    public final void k4(boolean z, boolean z2) throws JSONException {
        AdOverlayInfoParcel adOverlayInfoParcel;
        zzl zzlVar;
        AdOverlayInfoParcel adOverlayInfoParcel2;
        zzl zzlVar2;
        C2601s7 c2601s7 = AbstractC2773w7.c1;
        r rVar = r.d;
        boolean z3 = true;
        boolean z4 = ((Boolean) rVar.c.a(c2601s7)).booleanValue() && (adOverlayInfoParcel2 = this.c) != null && (zzlVar2 = adOverlayInfoParcel2.o) != null && zzlVar2.h;
        C2601s7 c2601s72 = AbstractC2773w7.d1;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        boolean z5 = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue() && (adOverlayInfoParcel = this.c) != null && (zzlVar = adOverlayInfoParcel.o) != null && zzlVar.i;
        if (z && z2 && z4 && !z5) {
            InterfaceC2529qe interfaceC2529qe = this.d;
            try {
                JSONObject jSONObjectPut = new JSONObject().put("message", "Custom close has been disabled for interstitial ads in this ad slot.").put("action", "useCustomClose");
                if (interfaceC2529qe != null) {
                    interfaceC2529qe.b("onError", jSONObjectPut);
                }
            } catch (JSONException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Error occurred while dispatching error event.", e);
            }
        }
        l lVar = this.f;
        if (lVar != null) {
            if (!z5 && (!z2 || z4)) {
                z3 = false;
            }
            ImageButton imageButton = lVar.a;
            if (!z3) {
                imageButton.setVisibility(0);
                return;
            }
            imageButton.setVisibility(8);
            if (((Long) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.g1)).longValue() > 0) {
                imageButton.animate().cancel();
                imageButton.clearAnimation();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void l() {
        InterfaceC2529qe interfaceC2529qe = this.d;
        if (interfaceC2529qe != null) {
            try {
                this.l.removeView(interfaceC2529qe.N());
            } catch (NullPointerException unused) {
            }
        }
        N();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void m1(int i, int i2, Intent intent) {
        Hk hk;
        AdOverlayInfoParcel adOverlayInfoParcel;
        if (i == 236) {
            C2601s7 c2601s7 = AbstractC2773w7.ad;
            r rVar = r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                A.l("Callback from intent launch with requestCode: 236 and resultCode: " + i2);
                InterfaceC2529qe interfaceC2529qe = this.d;
                if (interfaceC2529qe == null || interfaceC2529qe.L() == null || (hk = interfaceC2529qe.L().z) == null || (adOverlayInfoParcel = this.c) == null || !((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    return;
                }
                Fi fiA = hk.a();
                fiA.o("action", "hilca");
                String str = adOverlayInfoParcel.q;
                if (str == null) {
                    str = "";
                }
                fiA.o("gqi", str);
                StringBuilder sb = new StringBuilder();
                sb.append(i2);
                fiA.o("hilr", sb.toString());
                if (i2 == -1 && intent != null) {
                    String stringExtra = intent.getStringExtra("callerPackage");
                    String stringExtra2 = intent.getStringExtra("loadingStage");
                    if (stringExtra != null) {
                        fiA.o("hilcp", stringExtra);
                    }
                    if (stringExtra2 != null) {
                        fiA.o("hills", stringExtra2);
                    }
                }
                ((Hk) fiA.c).b.execute(new Fk(fiA, 2));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void p() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public void p2(Bundle bundle) throws JSONException, e {
        switch (this.x) {
            case 4:
                A.l("AdOverlayParcel is null or does not contain valid overlay type.");
                this.w = 4;
                this.b.finish();
                return;
            default:
                if (!this.r) {
                    this.b.requestWindowFeature(1);
                }
                this.j = bundle != null && bundle.getBoolean("com.google.android.gms.ads.internal.overlay.hasResumed", false);
                try {
                    Activity activity = this.b;
                    AdOverlayInfoParcel adOverlayInfoParcelA = AdOverlayInfoParcel.a(activity.getIntent());
                    this.c = adOverlayInfoParcelA;
                    if (adOverlayInfoParcelA == null) {
                        throw new e("Could not get info for ad overlay.");
                    }
                    if (adOverlayInfoParcelA.w) {
                        if (Build.VERSION.SDK_INT >= 28) {
                            activity.setShowWhenLocked(true);
                        } else {
                            activity.getWindow().addFlags(524288);
                        }
                    }
                    if (this.c.m.c > 7500000) {
                        this.w = 4;
                    }
                    if (activity.getIntent() != null) {
                        this.u = activity.getIntent().getBooleanExtra("shouldCallOnOverlayOpened", true);
                    }
                    AdOverlayInfoParcel adOverlayInfoParcel = this.c;
                    zzl zzlVar = adOverlayInfoParcel.o;
                    if (zzlVar != null) {
                        boolean z = zzlVar.a;
                        this.k = z;
                        if (z) {
                            if (adOverlayInfoParcel.k != 5 && zzlVar.f != -1) {
                                new g(this, 0).R();
                            }
                        }
                    } else if (adOverlayInfoParcel.k == 5) {
                        this.k = true;
                        if (adOverlayInfoParcel.k != 5) {
                            new g(this, 0).R();
                        }
                    } else {
                        this.k = false;
                    }
                    if (bundle == null) {
                        if (this.u) {
                            C2058fh c2058fh = this.c.t;
                            if (c2058fh != null) {
                                synchronized (c2058fh) {
                                    ScheduledFuture scheduledFuture = c2058fh.d;
                                    if (scheduledFuture != null) {
                                        scheduledFuture.cancel(true);
                                    }
                                }
                            }
                            j jVar = this.c.c;
                            if (jVar != null) {
                                jVar.I3();
                            }
                        }
                        AdOverlayInfoParcel adOverlayInfoParcel2 = this.c;
                        if (adOverlayInfoParcel2.k != 1) {
                            InterfaceC1582a interfaceC1582a = adOverlayInfoParcel2.b;
                            if (interfaceC1582a != null) {
                                interfaceC1582a.onAdClicked();
                            }
                            InterfaceC2447oi interfaceC2447oi = this.c.u;
                            if (interfaceC2447oi != null) {
                                interfaceC2447oi.c0();
                            }
                        }
                    }
                    AdOverlayInfoParcel adOverlayInfoParcel3 = this.c;
                    f fVar = new f(activity, adOverlayInfoParcel3.n, adOverlayInfoParcel3.m.a, adOverlayInfoParcel3.s);
                    this.l = fVar;
                    fVar.setId(1000);
                    com.google.android.gms.ads.internal.j.C.f.d(activity);
                    AdOverlayInfoParcel adOverlayInfoParcel4 = this.c;
                    int i = adOverlayInfoParcel4.k;
                    if (i == 1) {
                        f4(false);
                        return;
                    }
                    if (i == 2) {
                        this.e = new com.google.android.gms.cloudmessaging.k(adOverlayInfoParcel4.d);
                        f4(false);
                        return;
                    } else if (i == 3) {
                        f4(true);
                        return;
                    } else {
                        if (i != 5) {
                            throw new e("Could not determine ad overlay type.");
                        }
                        f4(false);
                        return;
                    }
                } catch (e e) {
                    com.google.android.gms.ads.internal.util.client.i.h(e.getMessage());
                    this.w = 4;
                    this.b.finish();
                    return;
                }
        }
    }

    public final void q() {
        InterfaceC2529qe interfaceC2529qe;
        j jVar;
        if (this.t) {
            return;
        }
        this.t = true;
        InterfaceC2529qe interfaceC2529qe2 = this.d;
        if (interfaceC2529qe2 != null) {
            this.l.removeView(interfaceC2529qe2.N());
            com.google.android.gms.cloudmessaging.k kVar = this.e;
            if (kVar != null) {
                this.d.F((Context) kVar.c);
                this.d.I0(false);
                if (((Boolean) r.d.c.a(AbstractC2773w7.Fc)).booleanValue() && this.d.getParent() != null) {
                    ((ViewGroup) this.d.getParent()).removeView(this.d.N());
                }
                ViewGroup viewGroup = (ViewGroup) this.e.e;
                View viewN = this.d.N();
                com.google.android.gms.cloudmessaging.k kVar2 = this.e;
                viewGroup.addView(viewN, kVar2.b, (ViewGroup.LayoutParams) kVar2.d);
                this.e = null;
            } else {
                Activity activity = this.b;
                if (activity.getApplicationContext() != null) {
                    this.d.F(activity.getApplicationContext());
                }
            }
            this.d = null;
        }
        AdOverlayInfoParcel adOverlayInfoParcel = this.c;
        if (adOverlayInfoParcel != null && (jVar = adOverlayInfoParcel.c) != null) {
            jVar.X(this.w);
        }
        AdOverlayInfoParcel adOverlayInfoParcel2 = this.c;
        if (adOverlayInfoParcel2 == null || (interfaceC2529qe = adOverlayInfoParcel2.d) == null) {
            return;
        }
        i4(this.c.d.N(), interfaceC2529qe.g0());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void s() {
        if (((Boolean) r.d.c.a(AbstractC2773w7.a5)).booleanValue()) {
            InterfaceC2529qe interfaceC2529qe = this.d;
            if (interfaceC2529qe == null || interfaceC2529qe.B()) {
                com.google.android.gms.ads.internal.util.client.i.h("The webview does not exist. Ignoring action.");
            } else {
                this.d.onResume();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final boolean s3() {
        this.w = 1;
        if (this.d == null) {
            return true;
        }
        if (((Boolean) r.d.c.a(AbstractC2773w7.U8)).booleanValue() && this.d.canGoBack()) {
            this.d.goBack();
            return false;
        }
        boolean zS0 = this.d.S0();
        if (!zS0) {
            this.d.j("onbackblocked", Collections.EMPTY_MAP);
        }
        return zS0;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void v() {
        j jVar;
        h();
        AdOverlayInfoParcel adOverlayInfoParcel = this.c;
        if (adOverlayInfoParcel != null && (jVar = adOverlayInfoParcel.c) != null) {
            jVar.Y3();
        }
        if (!((Boolean) r.d.c.a(AbstractC2773w7.a5)).booleanValue() && this.d != null && (!this.b.isFinishing() || this.e == null)) {
            this.d.onPause();
        }
        N();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void v2(com.google.android.gms.dynamic.a aVar) {
        h4((Configuration) com.google.android.gms.dynamic.b.I3(aVar));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void w() {
        j jVar;
        AdOverlayInfoParcel adOverlayInfoParcel = this.c;
        if (adOverlayInfoParcel != null && (jVar = adOverlayInfoParcel.c) != null) {
            jVar.v3();
        }
        h4(this.b.getResources().getConfiguration());
        if (((Boolean) r.d.c.a(AbstractC2773w7.a5)).booleanValue()) {
            return;
        }
        InterfaceC2529qe interfaceC2529qe = this.d;
        if (interfaceC2529qe == null || interfaceC2529qe.B()) {
            com.google.android.gms.ads.internal.util.client.i.h("The webview does not exist. Ignoring action.");
        } else {
            this.d.onResume();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void y() {
        this.r = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void zzi() {
        this.w = 1;
    }
}
