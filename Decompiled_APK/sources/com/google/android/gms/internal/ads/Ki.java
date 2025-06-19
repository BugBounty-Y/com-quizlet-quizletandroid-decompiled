package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Point;
import android.os.Bundle;
import android.os.RemoteException;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ImageView;
import com.google.android.gms.ads.internal.client.C1591e0;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1595g0;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Ki implements InterfaceC1886bj {
    public C1591e0 C;
    public final Ah D;
    public final C2276kj E;
    public final com.google.android.gms.ads.internal.a F;
    public final Context a;
    public final C1929cj b;
    public final JSONObject c;
    public final C1843ak d;
    public final Yi e;
    public final P4 f;
    public final C2146hh g;
    public final Vg h;
    public final C2404ni i;
    public final Vp j;
    public final VersionInfoParcel k;
    public final C2023eq l;
    public final C1724Kf m;
    public final ViewOnClickListenerC2362mj n;
    public final com.google.android.gms.common.util.a o;
    public final C2361mi p;
    public final C2584rr q;
    public final C2535qk r;
    public final Tq s;
    public final BinderC2408nm t;
    public boolean v;
    public boolean u = false;
    public boolean w = false;
    public boolean x = false;
    public Point y = new Point();
    public Point z = new Point();
    public long A = 0;
    public long B = 0;

    public Ki(Context context, C1929cj c1929cj, JSONObject jSONObject, C1843ak c1843ak, Yi yi, P4 p4, C2146hh c2146hh, Vg vg, C2404ni c2404ni, Vp vp, VersionInfoParcel versionInfoParcel, C2023eq c2023eq, C1724Kf c1724Kf, ViewOnClickListenerC2362mj viewOnClickListenerC2362mj, com.google.android.gms.common.util.a aVar, C2361mi c2361mi, C2584rr c2584rr, Tq tq, BinderC2408nm binderC2408nm, C2535qk c2535qk, C2276kj c2276kj, Ah ah, com.google.android.gms.ads.internal.a aVar2) {
        this.a = context;
        this.b = c1929cj;
        this.c = jSONObject;
        this.d = c1843ak;
        this.e = yi;
        this.f = p4;
        this.g = c2146hh;
        this.h = vg;
        this.i = c2404ni;
        this.j = vp;
        this.k = versionInfoParcel;
        this.l = c2023eq;
        this.m = c1724Kf;
        this.n = viewOnClickListenerC2362mj;
        this.o = aVar;
        this.p = c2361mi;
        this.q = c2584rr;
        this.s = tq;
        this.t = binderC2408nm;
        this.r = c2535qk;
        this.E = c2276kj;
        this.D = ah;
        this.F = aVar2;
    }

    public final void A() {
        try {
            C1591e0 c1591e0 = this.C;
            if (c1591e0 != null) {
                c1591e0.d4(1, c1591e0.f3());
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void B() {
        this.x = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x009c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void C(android.view.View r13, org.json.JSONObject r14, org.json.JSONObject r15, org.json.JSONObject r16, org.json.JSONObject r17, java.lang.String r18, org.json.JSONObject r19, org.json.JSONObject r20, boolean r21, boolean r22) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 431
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ki.C(android.view.View, org.json.JSONObject, org.json.JSONObject, org.json.JSONObject, org.json.JSONObject, java.lang.String, org.json.JSONObject, org.json.JSONObject, boolean, boolean):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final boolean J() {
        return this.c.optBoolean("allow_custom_click_gesture", false);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void T(String str) throws JSONException {
        C(null, null, null, null, null, str, null, null, false, false);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void a(View view, Map map, Map map2, ImageView.ScaleType scaleType) throws JSONException {
        Context context = this.a;
        JSONObject jSONObjectE = com.google.android.gms.internal.mlkit_vision_common.W2.e(context, map, map2, view, scaleType);
        JSONObject jSONObjectI = com.google.android.gms.internal.mlkit_vision_common.W2.i(context, view);
        JSONObject jSONObjectH = com.google.android.gms.internal.mlkit_vision_common.W2.h(view);
        JSONObject jSONObjectF = com.google.android.gms.internal.mlkit_vision_common.W2.f(context, view);
        boolean zJ = com.google.android.gms.internal.mlkit_vision_common.W2.j(context, this.j);
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("ad", this.c);
            jSONObject.put("asset_view_signal", jSONObjectE);
            jSONObject.put("ad_view_signal", jSONObjectI);
            jSONObject.put("scroll_view_signal", jSONObjectH);
            jSONObject.put("lock_screen_signal", jSONObjectF);
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F3)).booleanValue()) {
                jSONObject.put("view_signals", u(view));
            }
            jSONObject.put("policy_validator_enabled", zJ);
            jSONObject.put("screen", com.google.android.gms.internal.mlkit_vision_common.W2.g(context));
            AbstractC1972di.f(this.d.a("google.afma.nativeAds.handleNativeAdSignalsLogging", jSONObject), "Error during performing handleNativeAdSignalsLogging");
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to create native ad signals logging JSON.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void b(View view, Map map, Map map2, InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj, InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj2) {
        this.y = new Point();
        this.z = new Point();
        if (!this.v) {
            this.p.k1(view);
            this.v = true;
        }
        view.setOnTouchListener(interfaceViewOnClickListenerC2705uj);
        view.setClickable(true);
        view.setOnClickListener(interfaceViewOnClickListenerC2705uj2);
        C1724Kf c1724Kf = this.m;
        c1724Kf.getClass();
        c1724Kf.j = new WeakReference(this);
        boolean zK = com.google.android.gms.internal.mlkit_vision_common.W2.k(this.k.c);
        if (map != null) {
            Iterator it2 = map.entrySet().iterator();
            while (it2.hasNext()) {
                View view2 = (View) ((WeakReference) ((Map.Entry) it2.next()).getValue()).get();
                if (view2 != null) {
                    if (zK) {
                        view2.setOnTouchListener(interfaceViewOnClickListenerC2705uj);
                    }
                    view2.setClickable(true);
                    view2.setOnClickListener(interfaceViewOnClickListenerC2705uj2);
                }
            }
        }
        if (map2 != null) {
            Iterator it3 = map2.entrySet().iterator();
            while (it3.hasNext()) {
                View view3 = (View) ((WeakReference) ((Map.Entry) it3.next()).getValue()).get();
                if (view3 != null) {
                    if (zK) {
                        view3.setOnTouchListener(interfaceViewOnClickListenerC2705uj);
                    }
                    view3.setClickable(false);
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void c() throws JSONException {
        y(null, null, null, null, null, null, false, null);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void d(Bundle bundle) {
        if (bundle == null) {
            com.google.android.gms.ads.internal.util.client.i.d("Touch event data is null. No touch event is reported.");
            return;
        }
        if (!x("touch_reporting")) {
            com.google.android.gms.ads.internal.util.client.i.e("The ad slot cannot handle external touch events. You must be in the allow list to be able to report your touch events.");
            return;
        }
        this.f.b.g((int) bundle.getFloat("x"), (int) bundle.getFloat("y"), bundle.getInt("duration_ms"));
        w();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final boolean e() {
        if (zza() == 0) {
            return true;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.zb)).booleanValue()) {
            return this.l.i.j;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void f(View view) {
        this.y = new Point();
        this.z = new Point();
        if (view != null) {
            C2361mi c2361mi = this.p;
            synchronized (c2361mi) {
                WeakHashMap weakHashMap = c2361mi.c;
                if (weakHashMap.containsKey(view)) {
                    ((F5) weakHashMap.get(view)).l.remove(c2361mi);
                    weakHashMap.remove(view);
                }
            }
        }
        this.v = false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void g(Bundle bundle) throws JSONException {
        if (bundle == null) {
            com.google.android.gms.ads.internal.util.client.i.d("Click data is null. No click is reported.");
            return;
        }
        if (!x("click_reporting")) {
            com.google.android.gms.ads.internal.util.client.i.e("The ad slot cannot handle external click events. You must be part of the allow list to be able to report your click events.");
            return;
        }
        Bundle bundle2 = bundle.getBundle("click_signal");
        JSONObject jSONObjectH = null;
        String string = bundle2 != null ? bundle2.getString("asset_id") : null;
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        cVar.getClass();
        try {
            jSONObjectH = cVar.h(bundle);
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error converting Bundle to JSON", e);
        }
        C(null, null, null, null, null, string, null, jSONObjectH, false, false);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void h(View view, Map map, Map map2, ImageView.ScaleType scaleType) throws JSONException {
        Context context = this.a;
        y(com.google.android.gms.internal.mlkit_vision_common.W2.i(context, view), com.google.android.gms.internal.mlkit_vision_common.W2.e(context, map, map2, view, scaleType), com.google.android.gms.internal.mlkit_vision_common.W2.h(view), com.google.android.gms.internal.mlkit_vision_common.W2.f(context, view), u(view), null, com.google.android.gms.internal.mlkit_vision_common.W2.j(context, this.j), view);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void i() {
        View view;
        if (this.c.optBoolean("custom_one_point_five_click_enabled", false)) {
            ViewOnClickListenerC2362mj viewOnClickListenerC2362mj = this.n;
            if (viewOnClickListenerC2362mj.c == null || viewOnClickListenerC2362mj.f == null) {
                return;
            }
            viewOnClickListenerC2362mj.e = null;
            viewOnClickListenerC2362mj.f = null;
            WeakReference weakReference = viewOnClickListenerC2362mj.g;
            if (weakReference != null && (view = (View) weakReference.get()) != null) {
                view.setClickable(false);
                view.setOnClickListener(null);
                viewOnClickListenerC2362mj.g = null;
            }
            try {
                V8 v8 = viewOnClickListenerC2362mj.c;
                v8.d4(2, v8.f3());
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0025  */
    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j(android.view.View r17, android.view.View r18, java.util.Map r19, java.util.Map r20, boolean r21, android.widget.ImageView.ScaleType r22, int r23) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ki.j(android.view.View, android.view.View, java.util.Map, java.util.Map, boolean, android.widget.ImageView$ScaleType, int):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void k(View view, MotionEvent motionEvent) {
        int[] iArr = new int[2];
        if (view != null) {
            view.getLocationOnScreen(iArr);
        }
        this.y = new Point(((int) motionEvent.getRawX()) - iArr[0], ((int) motionEvent.getRawY()) - iArr[1]);
        long jCurrentTimeMillis = this.o.currentTimeMillis();
        this.B = jCurrentTimeMillis;
        if (motionEvent.getAction() == 0) {
            this.r.a = motionEvent;
            this.A = jCurrentTimeMillis;
            this.z = this.y;
        }
        MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
        Point point = this.y;
        motionEventObtain.setLocation(point.x, point.y);
        this.f.b.h(motionEventObtain);
        motionEventObtain.recycle();
        w();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void l(V8 v8) {
        if (!this.c.optBoolean("custom_one_point_five_click_enabled", false)) {
            com.google.android.gms.ads.internal.util.client.i.h("setUnconfirmedClickListener: Your account need to be in the allow list to use this feature.\nContact your account manager for more information.");
            return;
        }
        ViewOnClickListenerC2362mj viewOnClickListenerC2362mj = this.n;
        viewOnClickListenerC2362mj.c = v8;
        C2217j9 c2217j9 = viewOnClickListenerC2362mj.d;
        C1843ak c1843ak = viewOnClickListenerC2362mj.a;
        if (c2217j9 != null) {
            c1843ak.d("/unconfirmedClick", c2217j9);
        }
        C2217j9 c2217j92 = new C2217j9(4, viewOnClickListenerC2362mj, v8);
        viewOnClickListenerC2362mj.d = c2217j92;
        c1843ak.c("/unconfirmedClick", c2217j92);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void m(View view, View view2, Map map, Map map2, boolean z, ImageView.ScaleType scaleType) throws JSONException {
        Context context = this.a;
        JSONObject jSONObjectE = com.google.android.gms.internal.mlkit_vision_common.W2.e(context, map, map2, view2, scaleType);
        JSONObject jSONObjectI = com.google.android.gms.internal.mlkit_vision_common.W2.i(context, view2);
        JSONObject jSONObjectH = com.google.android.gms.internal.mlkit_vision_common.W2.h(view2);
        JSONObject jSONObjectF = com.google.android.gms.internal.mlkit_vision_common.W2.f(context, view2);
        String strV = v(view, map);
        C(true == ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M3)).booleanValue() ? view2 : view, jSONObjectI, jSONObjectE, jSONObjectH, jSONObjectF, strV, com.google.android.gms.internal.mlkit_vision_common.W2.d(strV, context, this.z, this.y), null, z, false);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void n() {
        C1843ak c1843ak = this.d;
        synchronized (c1843ak) {
            C2889yv c2889yv = c1843ak.m;
            if (c2889yv == null) {
                return;
            }
            C2147hi c2147hi = new C2147hi(11, (byte) 0);
            c2889yv.a(new Qv(0, c2889yv, c2147hi), c1843ak.e);
            c1843ak.m = null;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final JSONObject o(View view, Map map, Map map2, ImageView.ScaleType scaleType) throws JSONException {
        JSONObject jSONObjectS = s(view, map, map2, scaleType);
        JSONObject jSONObject = new JSONObject();
        try {
            if (this.x && this.c.optBoolean("allow_custom_click_gesture", false)) {
                jSONObject.put("custom_click_gesture_eligible", true);
            }
            if (jSONObjectS != null) {
                jSONObject.put("nas", jSONObjectS);
                return jSONObject;
            }
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to create native click meta data JSON.", e);
        }
        return jSONObject;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void p(View view) {
        if (!this.c.optBoolean("custom_one_point_five_click_enabled", false)) {
            com.google.android.gms.ads.internal.util.client.i.h("setClickConfirmingView: Your account need to be in the allow list to use this feature.\nContact your account manager for more information.");
        } else {
            if (view == null) {
                return;
            }
            ViewOnClickListenerC2362mj viewOnClickListenerC2362mj = this.n;
            view.setOnClickListener(viewOnClickListenerC2362mj);
            view.setClickable(true);
            viewOnClickListenerC2362mj.g = new WeakReference(view);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void q(InterfaceC1595g0 interfaceC1595g0) {
        com.google.android.gms.ads.internal.client.E0 e0;
        com.google.android.gms.ads.internal.client.E0 e02;
        try {
            if (this.w) {
                return;
            }
            Tq tq = this.s;
            Vp vp = this.j;
            C2584rr c2584rr = this.q;
            if (interfaceC1595g0 == null) {
                Yi yi = this.e;
                synchronized (yi) {
                    e0 = yi.g;
                }
                if (e0 != null) {
                    this.w = true;
                    synchronized (yi) {
                        e02 = yi.g;
                    }
                    c2584rr.a(e02.b, vp.x0, tq, null);
                    A();
                    return;
                }
            }
            this.w = true;
            c2584rr.a(interfaceC1595g0.f(), vp.x0, tq, null);
            A();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final boolean r(Bundle bundle) throws JSONException {
        JSONObject jSONObjectH;
        if (!x("impression_reporting")) {
            com.google.android.gms.ads.internal.util.client.i.e("The ad slot cannot handle external impression events. You must be in the allow list to be able to report your impression events.");
            return false;
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        cVar.getClass();
        if (bundle != null) {
            try {
                jSONObjectH = cVar.h(bundle);
            } catch (JSONException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Error converting Bundle to JSON", e);
            }
        } else {
            jSONObjectH = null;
        }
        return y(null, null, null, null, ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.vb)).booleanValue() ? u(null) : null, jSONObjectH, false, null);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final JSONObject s(View view, Map map, Map map2, ImageView.ScaleType scaleType) throws JSONException {
        Context context = this.a;
        JSONObject jSONObjectE = com.google.android.gms.internal.mlkit_vision_common.W2.e(context, map, map2, view, scaleType);
        JSONObject jSONObjectI = com.google.android.gms.internal.mlkit_vision_common.W2.i(context, view);
        JSONObject jSONObjectH = com.google.android.gms.internal.mlkit_vision_common.W2.h(view);
        JSONObject jSONObjectF = com.google.android.gms.internal.mlkit_vision_common.W2.f(context, view);
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("asset_view_signal", jSONObjectE);
            jSONObject.put("ad_view_signal", jSONObjectI);
            jSONObject.put("scroll_view_signal", jSONObjectH);
            jSONObject.put("lock_screen_signal", jSONObjectF);
            return jSONObject;
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to create native ad view signals JSON.", e);
            return null;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void t(C1591e0 c1591e0) {
        this.C = c1591e0;
    }

    public final String u(View view) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F3)).booleanValue()) {
            return null;
        }
        try {
            return this.f.b.i(this.a, view, null);
        } catch (Exception unused) {
            com.google.android.gms.ads.internal.util.client.i.e("Exception getting data.");
            return null;
        }
    }

    public final String v(View view, Map map) {
        if (map != null && view != null) {
            for (Map.Entry entry : map.entrySet()) {
                if (view.equals((View) ((WeakReference) entry.getValue()).get())) {
                    return (String) entry.getKey();
                }
            }
        }
        int iG = this.e.g();
        if (iG == 1) {
            return "1099";
        }
        if (iG == 2) {
            return "2099";
        }
        if (iG != 6) {
            return null;
        }
        return "3099";
    }

    public final void w() {
        com.google.android.gms.ads.internal.a aVar;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.rd)).booleanValue() || (aVar = this.F) == null) {
            return;
        }
        aVar.b = true;
    }

    public final boolean x(String str) {
        JSONObject jSONObjectOptJSONObject = this.c.optJSONObject("allow_pub_event_reporting");
        return jSONObjectOptJSONObject != null && jSONObjectOptJSONObject.optBoolean(str, false);
    }

    public final boolean y(JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3, JSONObject jSONObject4, String str, JSONObject jSONObject5, boolean z, View view) throws JSONException {
        Vp vp = this.j;
        Context context = this.a;
        try {
            JSONObject jSONObject6 = new JSONObject();
            jSONObject6.put("ad", this.c);
            jSONObject6.put("asset_view_signal", jSONObject2);
            jSONObject6.put("ad_view_signal", jSONObject);
            jSONObject6.put("scroll_view_signal", jSONObject3);
            jSONObject6.put("lock_screen_signal", jSONObject4);
            jSONObject6.put("provided_signals", jSONObject5);
            C2601s7 c2601s7 = AbstractC2773w7.F3;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                jSONObject6.put("view_signals", str);
            }
            jSONObject6.put("policy_validator_enabled", z);
            jSONObject6.put("screen", com.google.android.gms.internal.mlkit_vision_common.W2.g(context));
            boolean zBooleanValue = ((Boolean) rVar.c.a(AbstractC2773w7.E8)).booleanValue();
            C1843ak c1843ak = this.d;
            if (zBooleanValue) {
                c1843ak.c("/clickRecorded", new Ii(this, 1));
            } else {
                c1843ak.c("/logScionEvent", new Ii(this, 0));
            }
            c1843ak.c("/nativeImpression", new C2217j9(this, view));
            c1843ak.c("/nativeImpressionFlowControl", new Ji(this, this.q, vp.x0, this.s));
            AbstractC1972di.f(c1843ak.a("google.afma.nativeAds.handleImpression", jSONObject6), "Error during performing handleImpression");
            if (this.u) {
                return true;
            }
            this.u = com.google.android.gms.ads.internal.j.C.o.i(context, this.k.a, vp.C.toString(), this.l.f);
            return true;
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to create impression JSON.", e);
            return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void z() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("ad", this.c);
            AbstractC1972di.f(this.d.a("google.afma.nativeAds.handleDownloadedImpression", jSONObject), "Error during performing handleDownloadedImpression");
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final int zza() {
        zzbfv zzbfvVar = this.l.i;
        if (zzbfvVar == null) {
            return 0;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.zb)).booleanValue()) {
            return zzbfvVar.i;
        }
        return 0;
    }
}
