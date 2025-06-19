package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.BitmapFactory;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.text.TextUtils;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.hj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewTreeObserverOnGlobalLayoutListenerC2148hj extends B8 implements ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener, InterfaceViewOnClickListenerC2705uj {
    public static final Bu p;
    public final String b;
    public FrameLayout d;
    public FrameLayout e;
    public final C2227jd f;
    public View g;
    public Ui i;
    public F5 j;
    public InterfaceC2774w8 l;
    public boolean m;
    public GestureDetector o;
    public HashMap c = new HashMap();
    public com.google.android.gms.dynamic.a k = null;
    public boolean n = false;
    public final int h = ModuleDescriptor.MODULE_VERSION;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        Object[] objArr = {"2011", "1009", "3010"};
        AbstractC2457os.q(3, objArr);
        p = AbstractC2330lu.m(3, objArr);
    }

    public ViewTreeObserverOnGlobalLayoutListenerC2148hj(FrameLayout frameLayout, FrameLayout frameLayout2) {
        String str;
        ViewTreeObserver viewTreeObserver;
        ViewTreeObserver viewTreeObserver2 = null;
        this.d = frameLayout;
        this.e = frameLayout2;
        String canonicalName = frameLayout.getClass().getCanonicalName();
        if ("com.google.android.gms.ads.formats.NativeContentAdView".equals(canonicalName)) {
            str = "1007";
        } else if ("com.google.android.gms.ads.formats.NativeAppInstallAdView".equals(canonicalName)) {
            str = "2009";
        } else {
            "com.google.android.gms.ads.formats.UnifiedNativeAdView".equals(canonicalName);
            str = "3012";
        }
        this.b = str;
        L9 l9 = com.google.android.gms.ads.internal.j.C.B;
        ViewTreeObserverOnGlobalLayoutListenerC2442od viewTreeObserverOnGlobalLayoutListenerC2442od = new ViewTreeObserverOnGlobalLayoutListenerC2442od(frameLayout, this);
        View view = (View) ((WeakReference) viewTreeObserverOnGlobalLayoutListenerC2442od.a).get();
        ViewTreeObserver viewTreeObserver3 = (view == null || (viewTreeObserver3 = view.getViewTreeObserver()) == null || !viewTreeObserver3.isAlive()) ? null : viewTreeObserver3;
        if (viewTreeObserver3 != null) {
            viewTreeObserverOnGlobalLayoutListenerC2442od.k1(viewTreeObserver3);
        }
        ViewTreeObserverOnScrollChangedListenerC2485pd viewTreeObserverOnScrollChangedListenerC2485pd = new ViewTreeObserverOnScrollChangedListenerC2485pd(frameLayout, this);
        View view2 = (View) ((WeakReference) viewTreeObserverOnScrollChangedListenerC2485pd.a).get();
        if (view2 != null && (viewTreeObserver = view2.getViewTreeObserver()) != null && viewTreeObserver.isAlive()) {
            viewTreeObserver2 = viewTreeObserver;
        }
        if (viewTreeObserver2 != null) {
            viewTreeObserverOnScrollChangedListenerC2485pd.k1(viewTreeObserver2);
        }
        this.f = AbstractC2270kd.f;
        this.j = new F5(this.d.getContext(), this.d);
        frameLayout.setOnTouchListener(this);
        frameLayout.setOnClickListener(this);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized com.google.android.gms.dynamic.a C(String str) {
        return new com.google.android.gms.dynamic.b(Z(str));
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void D2(com.google.android.gms.dynamic.a aVar) {
        if (this.n) {
            return;
        }
        Object objI3 = com.google.android.gms.dynamic.b.I3(aVar);
        if (!(objI3 instanceof Ui)) {
            com.google.android.gms.ads.internal.util.client.i.h("Not an instance of native engine. This is most likely a transient error");
            return;
        }
        Ui ui = this.i;
        if (ui != null) {
            ui.g(this);
        }
        synchronized (this) {
            this.f.execute(new RunnableC2104gj(this, 0));
            Ui ui2 = (Ui) objI3;
            this.i = ui2;
            ui2.f(this);
            this.i.e(this.d);
            Ui ui3 = this.i;
            FrameLayout frameLayout = this.e;
            C2665tm c2665tmO = ui3.k.o();
            if (ui3.n.c() && c2665tmO != null && frameLayout != null) {
                C2147hi c2147hi = com.google.android.gms.ads.internal.j.C.x;
                Hr hr = c2665tmO.a;
                c2147hi.getClass();
                C2147hi.p(new RunnableC2451om(hr, frameLayout, 0));
            }
            if (this.m) {
                Wi wi = this.i.D;
                InterfaceC2774w8 interfaceC2774w8 = this.l;
                synchronized (wi) {
                    wi.a = interfaceC2774w8;
                }
            }
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Z3)).booleanValue() && !TextUtils.isEmpty(this.i.n.b())) {
                e4(this.i.n.b());
            }
            f4();
        }
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void K0(com.google.android.gms.dynamic.a aVar) {
        Ui ui = this.i;
        View view = (View) com.google.android.gms.dynamic.b.I3(aVar);
        synchronized (ui) {
            ui.l.p(view);
        }
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void V3(com.google.android.gms.dynamic.b bVar, int i) {
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void Y2(com.google.android.gms.dynamic.a aVar) {
        onTouch(this.d, (MotionEvent) com.google.android.gms.dynamic.b.I3(aVar));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized View Z(String str) {
        WeakReference weakReference;
        if (!this.n && (weakReference = (WeakReference) this.c.get(str)) != null) {
            return (View) weakReference.get();
        }
        return null;
    }

    public final synchronized void e4(String str) {
        DisplayMetrics displayMetrics;
        try {
            View frameLayout = new FrameLayout(this.e.getContext());
            frameLayout.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
            Context context = this.e.getContext();
            frameLayout.setClickable(false);
            frameLayout.setFocusable(false);
            if (!TextUtils.isEmpty(str)) {
                if (context.getApplicationContext() != null) {
                    context = context.getApplicationContext();
                }
                Resources resources = context.getResources();
                if (resources != null && (displayMetrics = resources.getDisplayMetrics()) != null) {
                    try {
                        byte[] bArrDecode = Base64.decode(str, 0);
                        BitmapDrawable bitmapDrawable = new BitmapDrawable(BitmapFactory.decodeByteArray(bArrDecode, 0, bArrDecode.length));
                        bitmapDrawable.setTargetDensity(displayMetrics.densityDpi);
                        Shader.TileMode tileMode = Shader.TileMode.REPEAT;
                        bitmapDrawable.setTileModeXY(tileMode, tileMode);
                        frameLayout.setBackground(bitmapDrawable);
                    } catch (IllegalArgumentException e) {
                        com.google.android.gms.ads.internal.util.client.i.i("Encountered invalid base64 watermark.", e);
                    }
                }
            }
            this.e.addView(frameLayout);
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final /* synthetic */ View f() {
        return this.d;
    }

    public final synchronized void f4() {
        int iZza;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.zb)).booleanValue()) {
            Ui ui = this.i;
            synchronized (ui) {
                iZza = ui.l.zza();
            }
            if (iZza != 0) {
                this.o = new GestureDetector(this.d.getContext(), new GestureDetectorOnGestureListenerC2319lj(this.i, this));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final FrameLayout g() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final com.google.android.gms.dynamic.a i() {
        return this.k;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized Map k() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized Map l() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized Map m() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void m2(com.google.android.gms.dynamic.a aVar) {
        if (this.n) {
            return;
        }
        this.k = aVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized String n() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized JSONObject o() {
        JSONObject jSONObjectO;
        Ui ui = this.i;
        if (ui == null) {
            return null;
        }
        FrameLayout frameLayout = this.d;
        Map mapK = k();
        Map mapL = l();
        synchronized (ui) {
            jSONObjectO = ui.l.o(frameLayout, mapK, mapL, ui.j());
        }
        return jSONObjectO;
    }

    @Override // android.view.View.OnClickListener
    public final synchronized void onClick(View view) {
        boolean zE;
        Ui ui = this.i;
        if (ui != null) {
            synchronized (ui) {
                zE = ui.l.e();
            }
            if (zE) {
                Ui ui2 = this.i;
                synchronized (ui2) {
                    ui2.l.i();
                }
                this.i.c(view, this.d, k(), l(), false);
            }
        }
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final synchronized void onGlobalLayout() {
        Ui ui = this.i;
        if (ui != null) {
            FrameLayout frameLayout = this.d;
            ui.b(frameLayout, k(), l(), Ui.h(frameLayout));
        }
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final synchronized void onScrollChanged() {
        Ui ui = this.i;
        if (ui != null) {
            FrameLayout frameLayout = this.d;
            ui.b(frameLayout, k(), l(), Ui.h(frameLayout));
        }
    }

    @Override // android.view.View.OnTouchListener
    public final synchronized boolean onTouch(View view, MotionEvent motionEvent) {
        int iZza;
        Ui ui = this.i;
        if (ui != null) {
            FrameLayout frameLayout = this.d;
            synchronized (ui) {
                ui.l.k(frameLayout, motionEvent);
            }
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.zb)).booleanValue() && this.o != null) {
                Ui ui2 = this.i;
                synchronized (ui2) {
                    iZza = ui2.l.zza();
                }
                if (iZza != 0) {
                    this.o.onTouchEvent(motionEvent);
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized void p3(View view, String str) {
        if (!this.n) {
            if (view == null) {
                this.c.remove(str);
                return;
            }
            this.c.put(str, new WeakReference(view));
            if (!"1098".equals(str) && !"3011".equals(str)) {
                if (com.google.android.gms.internal.mlkit_vision_common.W2.k(this.h)) {
                    view.setOnTouchListener(this);
                }
                view.setClickable(true);
                view.setOnClickListener(this);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void q() {
        try {
            if (this.n) {
                return;
            }
            Ui ui = this.i;
            if (ui != null) {
                ui.g(this);
                this.i = null;
            }
            this.c.clear();
            this.d.removeAllViews();
            this.e.removeAllViews();
            this.c = null;
            this.d = null;
            this.e = null;
            this.g = null;
            this.j = null;
            this.n = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void q1(InterfaceC2774w8 interfaceC2774w8) {
        if (!this.n) {
            this.m = true;
            this.l = interfaceC2774w8;
            Ui ui = this.i;
            if (ui != null) {
                Wi wi = ui.D;
                synchronized (wi) {
                    wi.a = interfaceC2774w8;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized JSONObject x() {
        JSONObject jSONObjectS;
        Ui ui = this.i;
        if (ui == null) {
            return null;
        }
        FrameLayout frameLayout = this.d;
        Map mapK = k();
        Map mapL = l();
        synchronized (ui) {
            jSONObjectS = ui.l.s(frameLayout, mapK, mapL, ui.j());
        }
        return jSONObjectS;
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final synchronized void y2(com.google.android.gms.dynamic.a aVar, String str) {
        p3((View) com.google.android.gms.dynamic.b.I3(aVar), str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final F5 zzi() {
        return this.j;
    }
}
