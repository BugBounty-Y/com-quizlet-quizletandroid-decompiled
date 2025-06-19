package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Qj extends AbstractBinderC2814x5 implements ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener, M9 {
    public View a;
    public com.google.android.gms.ads.internal.client.v0 b;
    public Ui c;
    public boolean d;
    public boolean e;

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        Wi wi;
        com.google.android.gms.ads.internal.client.v0 v0Var = null;
        interfaceC2774w8 = null;
        interfaceC2774w8 = null;
        InterfaceC2774w8 interfaceC2774w8 = null;
        O9 n9 = null;
        if (i == 3) {
            com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
            if (this.d) {
                com.google.android.gms.ads.internal.util.client.i.e("getVideoController: Instream ad should not be used after destroyed");
            } else {
                v0Var = this.b;
            }
            parcel2.writeNoException();
            AbstractC2857y5.e(parcel2, v0Var);
        } else if (i == 4) {
            com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
            g4();
            Ui ui = this.c;
            if (ui != null) {
                ui.r();
            }
            this.c = null;
            this.a = null;
            this.b = null;
            this.d = true;
            parcel2.writeNoException();
        } else if (i == 5) {
            com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder != null) {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.instream.client.IInstreamAdCallback");
                n9 = iInterfaceQueryLocalInterface instanceof O9 ? (O9) iInterfaceQueryLocalInterface : new N9(strongBinder, "com.google.android.gms.ads.internal.instream.client.IInstreamAdCallback", 0);
            }
            AbstractC2857y5.b(parcel);
            e4(aVarV3, n9);
            parcel2.writeNoException();
        } else if (i == 6) {
            com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
            e4(aVarV32, new Pj("com.google.android.gms.ads.internal.instream.client.IInstreamAdCallback"));
            parcel2.writeNoException();
        } else {
            if (i != 7) {
                return false;
            }
            com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
            if (this.d) {
                com.google.android.gms.ads.internal.util.client.i.e("getVideoController: Instream ad should not be used after destroyed");
            } else {
                Ui ui2 = this.c;
                if (ui2 != null && (wi = ui2.D) != null) {
                    synchronized (wi) {
                        interfaceC2774w8 = wi.a;
                    }
                }
            }
            parcel2.writeNoException();
            AbstractC2857y5.e(parcel2, interfaceC2774w8);
        }
        return true;
    }

    public final void e4(com.google.android.gms.dynamic.a aVar, O9 o9) {
        ViewTreeObserver viewTreeObserver;
        ViewTreeObserver viewTreeObserver2;
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        if (this.d) {
            com.google.android.gms.ads.internal.util.client.i.e("Instream ad can not be shown after destroy().");
            try {
                o9.u(2);
                return;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                return;
            }
        }
        View view = this.a;
        if (view == null || this.b == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Instream internal error: ".concat(view == null ? "can not get video view." : "can not get video controller."));
            try {
                o9.u(0);
                return;
            } catch (RemoteException e2) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
                return;
            }
        }
        if (this.e) {
            com.google.android.gms.ads.internal.util.client.i.e("Instream ad should not be used again.");
            try {
                o9.u(1);
                return;
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
                return;
            }
        }
        this.e = true;
        g4();
        ((ViewGroup) com.google.android.gms.dynamic.b.I3(aVar)).addView(this.a, new ViewGroup.LayoutParams(-1, -1));
        L9 l9 = com.google.android.gms.ads.internal.j.C.B;
        ViewTreeObserverOnGlobalLayoutListenerC2442od viewTreeObserverOnGlobalLayoutListenerC2442od = new ViewTreeObserverOnGlobalLayoutListenerC2442od(this.a, this);
        View view2 = (View) ((WeakReference) viewTreeObserverOnGlobalLayoutListenerC2442od.a).get();
        ViewTreeObserver viewTreeObserver3 = null;
        if (view2 == null || (viewTreeObserver = view2.getViewTreeObserver()) == null || !viewTreeObserver.isAlive()) {
            viewTreeObserver = null;
        }
        if (viewTreeObserver != null) {
            viewTreeObserverOnGlobalLayoutListenerC2442od.k1(viewTreeObserver);
        }
        ViewTreeObserverOnScrollChangedListenerC2485pd viewTreeObserverOnScrollChangedListenerC2485pd = new ViewTreeObserverOnScrollChangedListenerC2485pd(this.a, this);
        View view3 = (View) ((WeakReference) viewTreeObserverOnScrollChangedListenerC2485pd.a).get();
        if (view3 != null && (viewTreeObserver2 = view3.getViewTreeObserver()) != null && viewTreeObserver2.isAlive()) {
            viewTreeObserver3 = viewTreeObserver2;
        }
        if (viewTreeObserver3 != null) {
            viewTreeObserverOnScrollChangedListenerC2485pd.k1(viewTreeObserver3);
        }
        f4();
        try {
            o9.f();
        } catch (RemoteException e4) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e4);
        }
    }

    public final void f4() {
        View view;
        Ui ui = this.c;
        if (ui == null || (view = this.a) == null) {
            return;
        }
        Map map = Collections.EMPTY_MAP;
        ui.b(view, map, map, Ui.h(view));
    }

    public final void g4() {
        View view = this.a;
        if (view == null) {
            return;
        }
        ViewParent parent = view.getParent();
        if (parent instanceof ViewGroup) {
            ((ViewGroup) parent).removeView(this.a);
        }
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        f4();
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final void onScrollChanged() {
        f4();
    }
}
