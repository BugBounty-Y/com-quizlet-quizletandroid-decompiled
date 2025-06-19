package com.google.mlkit.common.internal.model;

import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import android.widget.CompoundButton;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.I;
import androidx.lifecycle.viewmodel.b;
import com.google.android.gms.ads.mediation.customevent.d;
import com.google.android.gms.internal.measurement.C2991f3;
import com.google.android.gms.internal.measurement.M3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.google.android.gms.tasks.c;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.h;
import com.google.android.material.bottomsheet.i;
import com.google.gson.internal.m;
import com.google.gson.internal.n;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class a implements b, androidx.arch.core.util.a, com.bumptech.glide.load.engine.bitmap_recycle.a, d, r, com.google.firebase.events.a, n, c, io.reactivex.rxjava3.functions.b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static void f(Context context, View view, String str) {
        boolean zK = P.k(context);
        OTLogger.c(str, 3, "useRTL: " + zK);
        if (zK) {
            view.setLayoutDirection(1);
        }
    }

    public static void g(Context context, h hVar) {
        int i;
        FrameLayout frameLayout = (FrameLayout) hVar.findViewById(R.id.design_bottom_sheet);
        if (frameLayout != null) {
            BottomSheetBehavior bottomSheetBehaviorC = BottomSheetBehavior.C(frameLayout);
            ViewGroup.LayoutParams layoutParams = frameLayout.getLayoutParams();
            if (context == null) {
                i = 0;
            } else {
                DisplayMetrics displayMetrics = new DisplayMetrics();
                ((Activity) context).getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
                i = displayMetrics.heightPixels;
            }
            if (layoutParams != null) {
                layoutParams.height = (i * 2) / 3;
            }
            frameLayout.setLayoutParams(layoutParams);
            bottomSheetBehaviorC.J(3);
            bottomSheetBehaviorC.I(frameLayout.getMeasuredHeight());
        }
    }

    public static void h(Context context, String str, ViewGroup viewGroup, int i) {
        if (viewGroup != null) {
            TextView textView = new TextView(context);
            textView.setVisibility(0);
            textView.setHeight(0);
            textView.setWidth(0);
            textView.setText(str);
            viewGroup.addView(textView);
            WeakHashMap weakHashMap = V.a;
            textView.setLabelFor(i);
        }
    }

    public static void i(View view, String str) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        view.setBackgroundColor(Color.parseColor(str));
    }

    public static void j(CompoundButton compoundButton, int i, int i2) {
        compoundButton.setButtonTintList(new ColorStateList(new int[][]{new int[]{android.R.attr.state_checked}, new int[0]}, new int[]{i, i2}));
    }

    public static void k(TextView textView, String str) {
        V.o(textView, new com.onetrust.otpublishers.headless.UI.extensions.c(str, 1));
    }

    public static void l(i iVar, I i, String str) {
        try {
            iVar.O(i.getSupportFragmentManager(), str);
        } catch (IllegalStateException e) {
            OTLogger.c("OneTrust", 3, "Activity in illegal state to add a Banner fragment " + e);
            if (i == null) {
                OTLogger.c("OneTrust", 6, "showUIOnForeground : Activity is null - ".concat(str));
            } else if (i.isDestroyed()) {
                OTLogger.c("OneTrust", 6, "showUIOnForeground : Activity is destroyed - ".concat(str));
            } else {
                i.getLifecycle().a(new com.onetrust.otpublishers.headless.UI.mobiledatautils.a(iVar, i, str));
            }
        }
    }

    public static boolean m(Context context) {
        if (!((AccessibilityManager) context.getSystemService("accessibility")).isEnabled()) {
            return false;
        }
        OTLogger.c("OneTrust", 3, "isAccessibilityEnabled - true");
        return true;
    }

    public static boolean n(Context context, String str) {
        if (context != null) {
            return true;
        }
        OTLogger.c("OneTrust", 6, "Context is null - ".concat(str));
        return false;
    }

    public static void o(i iVar, I i, String str) {
        AbstractC1136h0 supportFragmentManager = i.getSupportFragmentManager();
        supportFragmentManager.getClass();
        C1121a c1121a = new C1121a(supportFragmentManager);
        c1121a.k(iVar);
        iVar.n = false;
        iVar.o = true;
        c1121a.i(0, iVar, str, 1);
        iVar.m = false;
        iVar.i = c1121a.h(false, true);
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new m();
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public Bitmap a(int i, int i2, Bitmap.Config config) {
        return Bitmap.createBitmap(i, i2, config);
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t, Object u) {
        Intrinsics.checkNotNullExpressionValue(t, "t");
        Intrinsics.checkNotNullExpressionValue(u, "u");
        List list = (List) u;
        List list2 = (List) t;
        Intrinsics.d(list2);
        Intrinsics.d(list);
        return CollectionsKt.c0(list2, list);
    }

    public void b(Bitmap bitmap) {
        bitmap.recycle();
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public Bitmap c(int i, int i2, Bitmap.Config config) {
        return Bitmap.createBitmap(i, i2, config);
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public void d(int i) {
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.a
    public void e() {
    }

    public p p(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        g gVarT = userProps.t();
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.TRUE);
        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
        return com.google.android.gms.dynamite.d.b(gVarT, bVarF);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        Log.e("OptionalModuleUtils", "Failed to check feature availability", exc);
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) C2991f3.a.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                W3.b.get();
                Boolean bool2 = (Boolean) Y3.f.b();
                bool2.getClass();
                return bool2;
            case 12:
                List list3 = AbstractC3893t.a;
                Boolean bool3 = (Boolean) M3.a.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.r0.b();
            case 14:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.y.b();
                l.getClass();
                return l;
            case 15:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.m0.b();
                l2.getClass();
                return l2;
            case 16:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.o.b()).longValue());
            default:
                List list8 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.Y.b();
        }
    }

    @Override // androidx.arch.core.util.a
    /* renamed from: apply */
    public Object mo0apply(Object obj) {
        List list = (List) obj;
        if (list == null || list.size() <= 0) {
            return null;
        }
        return ((androidx.work.impl.model.p) list.get(0)).a();
    }
}
