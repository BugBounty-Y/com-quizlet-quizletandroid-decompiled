package com.google.android.material.bottomsheet;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Color;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.appcompat.app.D;
import androidx.appcompat.app.ViewOnClickListenerC0045a;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3275u6;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class h extends D {
    public BottomSheetBehavior f;
    public FrameLayout g;
    public CoordinatorLayout h;
    public FrameLayout i;
    public boolean j;
    public boolean k;
    public boolean l;
    public g m;
    public final boolean n;
    public com.quizlet.data.repository.folderwithcreator.e o;
    public final f p;

    public h(@NonNull Context context) {
        this(context, 0);
        this.n = getContext().getTheme().obtainStyledAttributes(new int[]{R.attr.enableEdgeToEdge}).getBoolean(0, false);
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public final void cancel() {
        g();
        super.cancel();
    }

    public final void f() throws Resources.NotFoundException {
        if (this.g == null) {
            FrameLayout frameLayout = (FrameLayout) View.inflate(getContext(), R.layout.design_bottom_sheet_dialog, null);
            this.g = frameLayout;
            this.h = (CoordinatorLayout) frameLayout.findViewById(R.id.coordinator);
            FrameLayout frameLayout2 = (FrameLayout) this.g.findViewById(R.id.design_bottom_sheet);
            this.i = frameLayout2;
            BottomSheetBehavior bottomSheetBehaviorC = BottomSheetBehavior.C(frameLayout2);
            this.f = bottomSheetBehaviorC;
            bottomSheetBehaviorC.w(this.p);
            this.f.H(this.j);
            this.o = new com.quizlet.data.repository.folderwithcreator.e(this.f, this.i);
        }
    }

    public final BottomSheetBehavior g() throws Resources.NotFoundException {
        if (this.f == null) {
            f();
        }
        return this.f;
    }

    public final FrameLayout h(View view, int i, ViewGroup.LayoutParams layoutParams) throws Resources.NotFoundException {
        f();
        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) this.g.findViewById(R.id.coordinator);
        if (i != 0 && view == null) {
            view = getLayoutInflater().inflate(i, (ViewGroup) coordinatorLayout, false);
        }
        if (this.n) {
            FrameLayout frameLayout = this.i;
            com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(this, 22);
            WeakHashMap weakHashMap = V.a;
            L.m(frameLayout, aVar);
        }
        this.i.removeAllViews();
        if (layoutParams == null) {
            this.i.addView(view);
        } else {
            this.i.addView(view, layoutParams);
        }
        coordinatorLayout.findViewById(R.id.touch_outside).setOnClickListener(new ViewOnClickListenerC0045a(this, 5));
        V.o(this.i, new androidx.viewpager.widget.e(this, 1));
        this.i.setOnTouchListener(new e(0));
        return this.g;
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        Window window = getWindow();
        if (window != null) {
            boolean z = this.n && Color.alpha(window.getNavigationBarColor()) < 255;
            FrameLayout frameLayout = this.g;
            if (frameLayout != null) {
                frameLayout.setFitsSystemWindows(!z);
            }
            CoordinatorLayout coordinatorLayout = this.h;
            if (coordinatorLayout != null) {
                coordinatorLayout.setFitsSystemWindows(!z);
            }
            AbstractC3275u6.b(window, !z);
            g gVar = this.m;
            if (gVar != null) {
                gVar.e(window);
            }
        }
        com.quizlet.data.repository.folderwithcreator.e eVar = this.o;
        if (eVar == null) {
            return;
        }
        boolean z2 = this.j;
        View view = (View) eVar.d;
        com.google.android.material.motion.c cVar = (com.google.android.material.motion.c) eVar.b;
        if (z2) {
            if (cVar != null) {
                cVar.b((com.google.android.material.motion.b) eVar.c, view, false);
            }
        } else if (cVar != null) {
            cVar.c(view);
        }
    }

    @Override // androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Window window = getWindow();
        if (window != null) {
            window.setStatusBarColor(0);
            window.addFlags(Integer.MIN_VALUE);
            window.setLayout(-1, -1);
        }
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public final void onDetachedFromWindow() {
        com.google.android.material.motion.c cVar;
        g gVar = this.m;
        if (gVar != null) {
            gVar.e(null);
        }
        com.quizlet.data.repository.folderwithcreator.e eVar = this.o;
        if (eVar == null || (cVar = (com.google.android.material.motion.c) eVar.b) == null) {
            return;
        }
        cVar.c((View) eVar.d);
    }

    @Override // androidx.activity.u, android.app.Dialog
    public final void onStart() {
        super.onStart();
        BottomSheetBehavior bottomSheetBehavior = this.f;
        if (bottomSheetBehavior == null || bottomSheetBehavior.L != 5) {
            return;
        }
        bottomSheetBehavior.J(4);
    }

    @Override // android.app.Dialog
    public final void setCancelable(boolean z) throws Resources.NotFoundException {
        com.quizlet.data.repository.folderwithcreator.e eVar;
        super.setCancelable(z);
        if (this.j != z) {
            this.j = z;
            BottomSheetBehavior bottomSheetBehavior = this.f;
            if (bottomSheetBehavior != null) {
                bottomSheetBehavior.H(z);
            }
            if (getWindow() == null || (eVar = this.o) == null) {
                return;
            }
            boolean z2 = this.j;
            View view = (View) eVar.d;
            com.google.android.material.motion.c cVar = (com.google.android.material.motion.c) eVar.b;
            if (z2) {
                if (cVar != null) {
                    cVar.b((com.google.android.material.motion.b) eVar.c, view, false);
                }
            } else if (cVar != null) {
                cVar.c(view);
            }
        }
    }

    @Override // android.app.Dialog
    public final void setCanceledOnTouchOutside(boolean z) {
        super.setCanceledOnTouchOutside(z);
        if (z && !this.j) {
            this.j = true;
        }
        this.k = z;
        this.l = true;
    }

    @Override // androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public final void setContentView(int i) {
        super.setContentView(h(null, i, null));
    }

    @Override // androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public final void setContentView(View view) {
        super.setContentView(h(view, 0, null));
    }

    @Override // androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public final void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        super.setContentView(h(view, 0, layoutParams));
    }

    public h(Context context, int i) {
        if (i == 0) {
            TypedValue typedValue = new TypedValue();
            i = context.getTheme().resolveAttribute(R.attr.bottomSheetDialogTheme, typedValue, true) ? typedValue.resourceId : R.style.Theme_Design_Light_BottomSheetDialog;
        }
        super(context, i);
        this.j = true;
        this.k = true;
        this.p = new f(this, 0);
        c().g(1);
        this.n = getContext().getTheme().obtainStyledAttributes(new int[]{R.attr.enableEdgeToEdge}).getBoolean(0, false);
    }
}
