package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.fj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewTreeObserverOnGlobalLayoutListenerC2060fj extends AbstractBinderC2814x5 implements ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener, InterfaceViewOnClickListenerC2705uj {
    public final WeakReference a;
    public final HashMap b;
    public final HashMap c;
    public final HashMap d;
    public Ui e;
    public final F5 f;

    public ViewTreeObserverOnGlobalLayoutListenerC2060fj(View view, HashMap map, HashMap map2) {
        ViewTreeObserver viewTreeObserver;
        super("com.google.android.gms.ads.internal.formats.client.INativeAdViewHolderDelegate");
        this.b = new HashMap();
        this.c = new HashMap();
        this.d = new HashMap();
        view.setOnTouchListener(this);
        view.setOnClickListener(this);
        L9 l9 = com.google.android.gms.ads.internal.j.C.B;
        ViewTreeObserverOnGlobalLayoutListenerC2442od viewTreeObserverOnGlobalLayoutListenerC2442od = new ViewTreeObserverOnGlobalLayoutListenerC2442od(view, this);
        View view2 = (View) ((WeakReference) viewTreeObserverOnGlobalLayoutListenerC2442od.a).get();
        ViewTreeObserver viewTreeObserver2 = null;
        ViewTreeObserver viewTreeObserver3 = (view2 == null || (viewTreeObserver3 = view2.getViewTreeObserver()) == null || !viewTreeObserver3.isAlive()) ? null : viewTreeObserver3;
        if (viewTreeObserver3 != null) {
            viewTreeObserverOnGlobalLayoutListenerC2442od.k1(viewTreeObserver3);
        }
        ViewTreeObserverOnScrollChangedListenerC2485pd viewTreeObserverOnScrollChangedListenerC2485pd = new ViewTreeObserverOnScrollChangedListenerC2485pd(view, this);
        View view3 = (View) ((WeakReference) viewTreeObserverOnScrollChangedListenerC2485pd.a).get();
        if (view3 != null && (viewTreeObserver = view3.getViewTreeObserver()) != null && viewTreeObserver.isAlive()) {
            viewTreeObserver2 = viewTreeObserver;
        }
        if (viewTreeObserver2 != null) {
            viewTreeObserverOnScrollChangedListenerC2485pd.k1(viewTreeObserver2);
        }
        this.a = new WeakReference(view);
        for (Map.Entry entry : map.entrySet()) {
            String str = (String) entry.getKey();
            View view4 = (View) entry.getValue();
            if (view4 != null) {
                this.b.put(str, new WeakReference(view4));
                if (!"1098".equals(str) && !"3011".equals(str)) {
                    view4.setOnTouchListener(this);
                    view4.setClickable(true);
                    view4.setOnClickListener(this);
                }
            }
        }
        this.d.putAll(this.b);
        for (Map.Entry entry2 : map2.entrySet()) {
            View view5 = (View) entry2.getValue();
            if (view5 != null) {
                this.c.put((String) entry2.getKey(), new WeakReference(view5));
                view5.setOnTouchListener(this);
                view5.setClickable(false);
            }
        }
        this.d.putAll(this.c);
        this.f = new F5(view.getContext(), view);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized View Z(String str) {
        WeakReference weakReference = (WeakReference) this.d.get(str);
        if (weakReference == null) {
            return null;
        }
        return (View) weakReference.get();
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            synchronized (this) {
                Object objI3 = com.google.android.gms.dynamic.b.I3(aVarV3);
                if (objI3 instanceof Ui) {
                    Ui ui = this.e;
                    if (ui != null) {
                        ui.g(this);
                    }
                    Ui ui2 = (Ui) objI3;
                    if (ui2.n.d()) {
                        this.e = ui2;
                        ui2.f(this);
                        this.e.e(f());
                    } else {
                        com.google.android.gms.ads.internal.util.client.i.e("Your account must be enabled to use this feature. Talk to your account manager to request this feature for your account.");
                    }
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("Not an instance of InternalNativeAd. This is most likely a transient error");
                }
            }
        } else if (i == 2) {
            synchronized (this) {
                Ui ui3 = this.e;
                if (ui3 != null) {
                    ui3.g(this);
                    this.e = null;
                }
            }
        } else {
            if (i != 3) {
                return false;
            }
            com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            synchronized (this) {
                try {
                    if (this.e != null) {
                        Object objI32 = com.google.android.gms.dynamic.b.I3(aVarV32);
                        if (!(objI32 instanceof View)) {
                            com.google.android.gms.ads.internal.util.client.i.h("Calling NativeAdViewHolderNonagonDelegate.setClickConfirmingView with wrong wrapped object");
                        }
                        Ui ui4 = this.e;
                        View view = (View) objI32;
                        synchronized (ui4) {
                            ui4.l.p(view);
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final View f() {
        return (View) this.a.get();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final FrameLayout g() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized com.google.android.gms.dynamic.a i() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized Map k() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized Map l() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized Map m() {
        return this.c;
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized String n() {
        return "1007";
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized JSONObject o() {
        JSONObject jSONObjectO;
        Ui ui = this.e;
        if (ui == null) {
            return null;
        }
        View viewF = f();
        Map mapK = k();
        Map mapL = l();
        synchronized (ui) {
            jSONObjectO = ui.l.o(viewF, mapK, mapL, ui.j());
        }
        return jSONObjectO;
    }

    @Override // android.view.View.OnClickListener
    public final synchronized void onClick(View view) {
        Ui ui = this.e;
        if (ui != null) {
            ui.c(view, f(), k(), l(), true);
        }
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final synchronized void onGlobalLayout() {
        Ui ui = this.e;
        if (ui != null) {
            ui.b(f(), k(), l(), Ui.h(f()));
        }
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final synchronized void onScrollChanged() {
        Ui ui = this.e;
        if (ui != null) {
            ui.b(f(), k(), l(), Ui.h(f()));
        }
    }

    @Override // android.view.View.OnTouchListener
    public final synchronized boolean onTouch(View view, MotionEvent motionEvent) {
        Ui ui = this.e;
        if (ui != null) {
            View viewF = f();
            synchronized (ui) {
                ui.l.k(viewF, motionEvent);
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized void p3(View view, String str) {
        this.d.put(str, new WeakReference(view));
        if (!"1098".equals(str) && !"3011".equals(str)) {
            this.b.put(str, new WeakReference(view));
            view.setClickable(true);
            view.setOnClickListener(this);
            view.setOnTouchListener(this);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final synchronized JSONObject x() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj
    public final F5 zzi() {
        return this.f;
    }
}
