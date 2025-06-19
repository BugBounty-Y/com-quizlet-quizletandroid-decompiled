package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.os.Looper;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.RelativeLayout;
import androidx.collection.C0209g;
import java.util.Collections;

/* renamed from: com.google.android.gms.internal.ads.nb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2397nb extends Fi {
    public String d;
    public boolean e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j;
    public int k;
    public final Object l;
    public final C2743ve m;
    public final Activity n;
    public com.bumptech.glide.load.engine.cache.f o;
    public ImageView p;
    public LinearLayout q;
    public final Os r;
    public PopupWindow s;
    public RelativeLayout t;
    public ViewGroup u;

    static {
        C0209g c0209g = new C0209g(7);
        Collections.addAll(c0209g, "top-left", "top-right", "top-center", "center", "bottom-left", "bottom-right", "bottom-center");
        Collections.unmodifiableSet(c0209g);
    }

    public C2397nb(C2743ve c2743ve, Os os) {
        super(9, c2743ve, "resize");
        this.d = "top-right";
        this.e = true;
        this.f = 0;
        this.g = 0;
        this.h = -1;
        this.i = 0;
        this.j = 0;
        this.k = -1;
        this.l = new Object();
        this.m = c2743ve;
        this.n = c2743ve.zzi();
        this.r = os;
    }

    public final void E(boolean z) {
        synchronized (this.l) {
            try {
                if (this.s != null) {
                    if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Oa)).booleanValue() || Looper.getMainLooper().getThread() == Thread.currentThread()) {
                        F(z);
                    } else {
                        AbstractC2270kd.f.a(new com.bumptech.glide.manager.o(z, 4, this));
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void F(boolean z) {
        C2601s7 c2601s7 = AbstractC2773w7.Pa;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        C2743ve c2743ve = this.m;
        if (zBooleanValue) {
            this.t.removeView(c2743ve);
            this.s.dismiss();
        } else {
            this.s.dismiss();
            this.t.removeView(c2743ve);
        }
        C2601s7 c2601s72 = AbstractC2773w7.Qa;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
            ViewParent parent = c2743ve.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(c2743ve);
            }
        }
        ViewGroup viewGroup = this.u;
        if (viewGroup != null) {
            viewGroup.removeView(this.p);
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Ra)).booleanValue()) {
                try {
                    this.u.addView(c2743ve);
                    c2743ve.k0(this.o);
                } catch (IllegalStateException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Unable to add webview back to view hierarchy.", e);
                }
            } else {
                this.u.addView(c2743ve);
                c2743ve.k0(this.o);
            }
        }
        if (z) {
            C("default");
            Os os = this.r;
            if (os != null) {
                ((C2363mk) os.b).c.j1(new C1927ch(3));
            }
        }
        this.s = null;
        this.t = null;
        this.u = null;
        this.q = null;
    }
}
