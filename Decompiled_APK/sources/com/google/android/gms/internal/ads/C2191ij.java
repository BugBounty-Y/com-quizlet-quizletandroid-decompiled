package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.ij, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2191ij {
    public static final ImageView.ScaleType k = ImageView.ScaleType.CENTER_INSIDE;
    public final com.google.android.gms.ads.internal.util.C a;
    public final C2023eq b;
    public final C1842aj c;
    public final Yi d;
    public final C2534qj e;
    public final C2662tj f;
    public final Executor g;
    public final Xv h;
    public final zzbfv i;
    public final Wi j;

    public C2191ij(com.google.android.gms.ads.internal.util.C c, C2023eq c2023eq, C1842aj c1842aj, Yi yi, C2534qj c2534qj, C2662tj c2662tj, Executor executor, Xv xv, Wi wi) {
        this.a = c;
        this.b = c2023eq;
        this.i = c2023eq.i;
        this.c = c1842aj;
        this.d = yi;
        this.e = c2534qj;
        this.f = c2662tj;
        this.g = executor;
        this.h = xv;
        this.j = wi;
    }

    public static void b(RelativeLayout.LayoutParams layoutParams, int i) {
        if (i == 0) {
            layoutParams.addRule(10);
            layoutParams.addRule(9);
        } else if (i == 2) {
            layoutParams.addRule(12);
            layoutParams.addRule(11);
        } else if (i != 3) {
            layoutParams.addRule(10);
            layoutParams.addRule(11);
        } else {
            layoutParams.addRule(12);
            layoutParams.addRule(9);
        }
    }

    public final void a(InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj) {
        if (interfaceViewOnClickListenerC2705uj == null) {
            return;
        }
        Context context = interfaceViewOnClickListenerC2705uj.f().getContext();
        if (com.google.android.gms.internal.mlkit_vision_common.W2.j(context, this.c.a)) {
            if (!(context instanceof Activity)) {
                com.google.android.gms.ads.internal.util.client.i.d("Activity context is needed for policy validator.");
                return;
            }
            C2662tj c2662tj = this.f;
            if (c2662tj == null || interfaceViewOnClickListenerC2705uj.g() == null) {
                return;
            }
            try {
                WindowManager windowManager = (WindowManager) context.getSystemService("window");
                windowManager.addView(c2662tj.a(interfaceViewOnClickListenerC2705uj.g(), windowManager), com.google.android.gms.internal.mlkit_vision_common.W2.c());
            } catch (zzcfn unused) {
                com.google.android.gms.ads.internal.util.A.m();
            }
        }
    }

    public final boolean c(ViewGroup viewGroup, boolean z) {
        View view;
        if (z) {
            Yi yi = this.d;
            synchronized (yi) {
                view = yi.o;
            }
        } else {
            Yi yi2 = this.d;
            synchronized (yi2) {
                view = yi2.p;
            }
        }
        if (view == null) {
            return false;
        }
        viewGroup.removeAllViews();
        if (view.getParent() instanceof ViewGroup) {
            ((ViewGroup) view.getParent()).removeView(view);
        }
        viewGroup.addView(view, ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.W3)).booleanValue() ? new FrameLayout.LayoutParams(-1, -1, 17) : new FrameLayout.LayoutParams(-2, -2, 17));
        return true;
    }
}
