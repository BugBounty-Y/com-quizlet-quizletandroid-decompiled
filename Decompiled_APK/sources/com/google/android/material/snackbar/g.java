package com.google.android.material.snackbar;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.animation.TimeInterpolator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityManager;
import android.view.animation.LinearInterpolator;
import androidx.core.view.L;
import androidx.core.view.V;
import com.bumptech.glide.load.engine.y;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.behavior.SwipeDismissBehavior;
import com.google.android.material.internal.p;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class g {
    public final int a;
    public final int b;
    public final int c;
    public final TimeInterpolator d;
    public final TimeInterpolator e;
    public final TimeInterpolator f;
    public final ViewGroup g;
    public final Context h;
    public final f i;
    public final SnackbarContentLayout j;
    public int k;
    public int m;
    public int n;
    public int o;
    public int p;
    public int q;
    public boolean r;
    public ArrayList s;
    public final AccessibilityManager t;
    public static final androidx.interpolator.view.animation.a v = com.google.android.material.animation.a.b;
    public static final LinearInterpolator w = com.google.android.material.animation.a.a;
    public static final androidx.interpolator.view.animation.a x = com.google.android.material.animation.a.d;
    public static final int[] z = {R.attr.snackbarStyle};
    public static final String A = g.class.getSimpleName();
    public static final Handler y = new Handler(Looper.getMainLooper(), new y(2));
    public final d l = new d(this, 0);
    public final e u = new e(this);

    public g(Context context, ViewGroup viewGroup, SnackbarContentLayout snackbarContentLayout, SnackbarContentLayout snackbarContentLayout2) {
        if (snackbarContentLayout == null) {
            throw new IllegalArgumentException("Transient bottom bar must have non-null content");
        }
        if (snackbarContentLayout2 == null) {
            throw new IllegalArgumentException("Transient bottom bar must have non-null callback");
        }
        this.g = viewGroup;
        this.j = snackbarContentLayout2;
        this.h = context;
        p.e(context, p.a, "Theme.AppCompat");
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(context);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(z);
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(0, -1);
        typedArrayObtainStyledAttributes.recycle();
        f fVar = (f) layoutInflaterFrom.inflate(resourceId != -1 ? R.layout.mtrl_layout_snackbar : R.layout.design_layout_snackbar, viewGroup, false);
        this.i = fVar;
        fVar.setBaseTransientBottomBar(this);
        float actionTextColorAlpha = fVar.getActionTextColorAlpha();
        if (actionTextColorAlpha != 1.0f) {
            snackbarContentLayout.b.setTextColor(X3.e(X3.b(R.attr.colorSurface, snackbarContentLayout), actionTextColorAlpha, snackbarContentLayout.b.getCurrentTextColor()));
        }
        snackbarContentLayout.setMaxInlineActionWidth(fVar.getMaxInlineActionWidth());
        fVar.addView(snackbarContentLayout);
        WeakHashMap weakHashMap = V.a;
        fVar.setAccessibilityLiveRegion(1);
        fVar.setImportantForAccessibility(1);
        fVar.setFitsSystemWindows(true);
        L.m(fVar, new com.airbnb.lottie.network.c(this, 25));
        V.o(fVar, new androidx.viewpager.widget.e(this, 6));
        this.t = (AccessibilityManager) context.getSystemService("accessibility");
        this.c = AbstractC3430b4.d(context, R.attr.motionDurationLong2, 250);
        this.a = AbstractC3430b4.d(context, R.attr.motionDurationLong2, 150);
        this.b = AbstractC3430b4.d(context, R.attr.motionDurationMedium1, 75);
        this.d = AbstractC3430b4.e(context, R.attr.motionEasingEmphasizedInterpolator, w);
        this.f = AbstractC3430b4.e(context, R.attr.motionEasingEmphasizedInterpolator, x);
        this.e = AbstractC3430b4.e(context, R.attr.motionEasingEmphasizedInterpolator, v);
    }

    public final void a(int i) {
        com.quizlet.data.repository.achievements.h hVarC = com.quizlet.data.repository.achievements.h.c();
        e eVar = this.u;
        synchronized (hVarC.a) {
            try {
                if (hVarC.e(eVar)) {
                    hVarC.a((i) hVarC.c, i);
                } else {
                    i iVar = (i) hVarC.d;
                    if (iVar != null && iVar.a.get() == eVar) {
                        hVarC.a((i) hVarC.d, i);
                    }
                }
            } finally {
            }
        }
    }

    public final boolean b() {
        boolean z2;
        com.quizlet.data.repository.achievements.h hVarC = com.quizlet.data.repository.achievements.h.c();
        e eVar = this.u;
        synchronized (hVarC.a) {
            z2 = true;
            if (!hVarC.e(eVar)) {
                i iVar = (i) hVarC.d;
                if (!(iVar != null && iVar.a.get() == eVar)) {
                    z2 = false;
                }
            }
        }
        return z2;
    }

    public final void c(int i) {
        com.quizlet.data.repository.achievements.h hVarC = com.quizlet.data.repository.achievements.h.c();
        e eVar = this.u;
        synchronized (hVarC.a) {
            try {
                if (hVarC.e(eVar)) {
                    hVarC.c = null;
                    if (((i) hVarC.d) != null) {
                        hVarC.k();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        ArrayList arrayList = this.s;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar = (com.quizlet.quizletandroid.ui.setcreation.fragments.i) this.s.get(size);
                iVar.getClass();
                h snackbar = (h) this;
                Intrinsics.checkNotNullParameter(snackbar, "snackbar");
                if (i != 1 && i != 3) {
                    com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) iVar.a).y;
                    iVar2.getClass();
                    DBTerm dBTerm = iVar.b;
                    dBTerm.setDeleted(true);
                    iVar2.d.c(dBTerm);
                    iVar2.g(iVar.c, iVar.d);
                    iVar2.e.a = false;
                }
            }
        }
        ViewParent parent = this.i.getParent();
        if (parent instanceof ViewGroup) {
            ((ViewGroup) parent).removeView(this.i);
        }
    }

    public final void d() {
        com.quizlet.data.repository.achievements.h hVarC = com.quizlet.data.repository.achievements.h.c();
        e eVar = this.u;
        synchronized (hVarC.a) {
            try {
                if (hVarC.e(eVar)) {
                    hVarC.j((i) hVarC.c);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        ArrayList arrayList = this.s;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((com.quizlet.quizletandroid.ui.setcreation.fragments.i) this.s.get(size)).getClass();
            }
        }
    }

    public final void e() {
        List<AccessibilityServiceInfo> enabledAccessibilityServiceList;
        boolean z2 = true;
        AccessibilityManager accessibilityManager = this.t;
        if (accessibilityManager != null && ((enabledAccessibilityServiceList = accessibilityManager.getEnabledAccessibilityServiceList(1)) == null || !enabledAccessibilityServiceList.isEmpty())) {
            z2 = false;
        }
        f fVar = this.i;
        if (z2) {
            fVar.post(new d(this, 2));
            return;
        }
        if (fVar.getParent() != null) {
            fVar.setVisibility(0);
        }
        d();
    }

    public final void f() {
        f fVar = this.i;
        ViewGroup.LayoutParams layoutParams = fVar.getLayoutParams();
        boolean z2 = layoutParams instanceof ViewGroup.MarginLayoutParams;
        String str = A;
        if (!z2) {
            Log.w(str, "Unable to update margins because layout params are not MarginLayoutParams");
            return;
        }
        if (fVar.j == null) {
            Log.w(str, "Unable to update margins because original view margins are not set");
            return;
        }
        if (fVar.getParent() == null) {
            return;
        }
        int i = this.m;
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        Rect rect = fVar.j;
        int i2 = rect.bottom + i;
        int i3 = rect.left + this.n;
        int i4 = rect.right + this.o;
        int i5 = rect.top;
        boolean z3 = (marginLayoutParams.bottomMargin == i2 && marginLayoutParams.leftMargin == i3 && marginLayoutParams.rightMargin == i4 && marginLayoutParams.topMargin == i5) ? false : true;
        if (z3) {
            marginLayoutParams.bottomMargin = i2;
            marginLayoutParams.leftMargin = i3;
            marginLayoutParams.rightMargin = i4;
            marginLayoutParams.topMargin = i5;
            fVar.requestLayout();
        }
        if ((z3 || this.q != this.p) && Build.VERSION.SDK_INT >= 29 && this.p > 0) {
            ViewGroup.LayoutParams layoutParams2 = fVar.getLayoutParams();
            if ((layoutParams2 instanceof androidx.coordinatorlayout.widget.e) && (((androidx.coordinatorlayout.widget.e) layoutParams2).a instanceof SwipeDismissBehavior)) {
                d dVar = this.l;
                fVar.removeCallbacks(dVar);
                fVar.post(dVar);
            }
        }
    }
}
