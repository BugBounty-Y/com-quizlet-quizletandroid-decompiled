package com.google.android.material.sidesheet;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Property;
import android.util.TypedValue;
import android.view.AbsSavedState;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.activity.C0030b;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.C0076c;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.RunnableC0133j;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.e;
import androidx.core.view.L;
import androidx.core.view.V;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.google.android.material.motion.h;
import com.google.android.material.motion.i;
import com.google.android.material.shape.g;
import com.google.android.material.shape.j;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class SideSheetBehavior<V extends View> extends androidx.coordinatorlayout.widget.b implements com.google.android.material.motion.b {
    public a a;
    public final g b;
    public final ColorStateList c;
    public final j d;
    public final k e;
    public final float f;
    public final boolean g;
    public int h;
    public androidx.customview.widget.d i;
    public boolean j;
    public final float k;
    public int l;
    public int m;
    public int n;
    public int o;
    public WeakReference p;
    public WeakReference q;
    public final int r;
    public VelocityTracker s;
    public i t;
    public int u;
    public final LinkedHashSet v;
    public final com.google.android.material.bottomsheet.b w;

    public SideSheetBehavior() {
        this.e = new k(this);
        this.g = true;
        this.h = 5;
        this.k = 0.1f;
        this.r = -1;
        this.v = new LinkedHashSet();
        this.w = new com.google.android.material.bottomsheet.b(this, 1);
    }

    public final void A() {
        View view;
        WeakReference weakReference = this.p;
        if (weakReference == null || (view = (View) weakReference.get()) == null) {
            return;
        }
        V.l(262144, view);
        V.i(0, view);
        V.l(1048576, view);
        V.i(0, view);
        int i = 5;
        if (this.h != 5) {
            V.m(view, androidx.core.view.accessibility.d.l, new b(this, i));
        }
        int i2 = 3;
        if (this.h != 3) {
            V.m(view, androidx.core.view.accessibility.d.j, new b(this, i2));
        }
    }

    @Override // com.google.android.material.motion.b
    public final void a(C0030b c0030b) {
        i iVar = this.t;
        if (iVar == null) {
            return;
        }
        iVar.f = c0030b;
    }

    @Override // com.google.android.material.motion.b
    public final void b(C0030b c0030b) {
        ViewGroup.MarginLayoutParams marginLayoutParams;
        i iVar = this.t;
        if (iVar == null) {
            return;
        }
        a aVar = this.a;
        int i = (aVar == null || aVar.d() == 0) ? 5 : 3;
        if (iVar.f == null) {
            Log.w("MaterialBackHelper", "Must call startBackProgress() before updateBackProgress()");
        }
        C0030b c0030b2 = iVar.f;
        iVar.f = c0030b;
        if (c0030b2 != null) {
            iVar.b(c0030b.c, c0030b.d == 0, i);
        }
        WeakReference weakReference = this.p;
        if (weakReference == null || weakReference.get() == null) {
            return;
        }
        View view = (View) this.p.get();
        WeakReference weakReference2 = this.q;
        View view2 = weakReference2 != null ? (View) weakReference2.get() : null;
        if (view2 == null || (marginLayoutParams = (ViewGroup.MarginLayoutParams) view2.getLayoutParams()) == null) {
            return;
        }
        this.a.e(marginLayoutParams, (int) ((view.getScaleX() * this.l) + this.o));
        view2.requestLayout();
    }

    @Override // com.google.android.material.motion.b
    public final void c() {
        int i;
        final ViewGroup.MarginLayoutParams marginLayoutParams;
        final int i2;
        i iVar = this.t;
        if (iVar == null) {
            return;
        }
        C0030b c0030b = iVar.f;
        ValueAnimator.AnimatorUpdateListener animatorUpdateListener = null;
        iVar.f = null;
        int i3 = 5;
        if (c0030b == null || Build.VERSION.SDK_INT < 34) {
            w(5);
            return;
        }
        a aVar = this.a;
        if (aVar != null && aVar.d() != 0) {
            i3 = 3;
        }
        C0076c c0076c = new C0076c(this, 10);
        WeakReference weakReference = this.q;
        final View view = weakReference != null ? (View) weakReference.get() : null;
        if (view != null && (marginLayoutParams = (ViewGroup.MarginLayoutParams) view.getLayoutParams()) != null) {
            switch (this.a.a) {
                case 0:
                    i2 = marginLayoutParams.leftMargin;
                    break;
                default:
                    i2 = marginLayoutParams.rightMargin;
                    break;
            }
            animatorUpdateListener = new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.sidesheet.c
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                    this.a.a.e(marginLayoutParams, com.google.android.material.animation.a.c(i2, valueAnimator.getAnimatedFraction(), 0));
                    view.requestLayout();
                }
            };
        }
        boolean z = c0030b.d == 0;
        WeakHashMap weakHashMap = V.a;
        View view2 = iVar.b;
        boolean z2 = (Gravity.getAbsoluteGravity(i3, view2.getLayoutDirection()) & 3) == 3;
        float scaleX = view2.getScaleX() * view2.getWidth();
        ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
        if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
            ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) layoutParams;
            i = z2 ? marginLayoutParams2.leftMargin : marginLayoutParams2.rightMargin;
        } else {
            i = 0;
        }
        float f = scaleX + i;
        Property property = View.TRANSLATION_X;
        if (z2) {
            f = -f;
        }
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(view2, (Property<View, Float>) property, f);
        if (animatorUpdateListener != null) {
            objectAnimatorOfFloat.addUpdateListener(animatorUpdateListener);
        }
        objectAnimatorOfFloat.setInterpolator(new androidx.interpolator.view.animation.a(1));
        objectAnimatorOfFloat.setDuration(com.google.android.material.animation.a.c(iVar.c, c0030b.c, iVar.d));
        objectAnimatorOfFloat.addListener(new h(iVar, z, i3));
        objectAnimatorOfFloat.addListener(c0076c);
        objectAnimatorOfFloat.start();
    }

    @Override // com.google.android.material.motion.b
    public final void d() {
        i iVar = this.t;
        if (iVar == null || iVar.a() == null) {
            return;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        View view = iVar.b;
        animatorSet.playTogether(ObjectAnimator.ofFloat(view, (Property<View, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(view, (Property<View, Float>) View.SCALE_Y, 1.0f));
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                animatorSet.playTogether(ObjectAnimator.ofFloat(viewGroup.getChildAt(i), (Property<View, Float>) View.SCALE_Y, 1.0f));
            }
        }
        animatorSet.setDuration(iVar.e);
        animatorSet.start();
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void g(e eVar) {
        this.p = null;
        this.i = null;
        this.t = null;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void j() {
        this.p = null;
        this.i = null;
        this.t = null;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean k(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        androidx.customview.widget.d dVar;
        VelocityTracker velocityTracker;
        if ((!view.isShown() && V.e(view) == null) || !this.g) {
            this.j = true;
            return false;
        }
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0 && (velocityTracker = this.s) != null) {
            velocityTracker.recycle();
            this.s = null;
        }
        if (this.s == null) {
            this.s = VelocityTracker.obtain();
        }
        this.s.addMovement(motionEvent);
        if (actionMasked == 0) {
            this.u = (int) motionEvent.getX();
        } else if ((actionMasked == 1 || actionMasked == 3) && this.j) {
            this.j = false;
            return false;
        }
        return (this.j || (dVar = this.i) == null || !dVar.p(motionEvent)) ? false : true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
        View view2;
        View view3;
        int left;
        int i2;
        int i3;
        View viewFindViewById;
        int iC = 0;
        g gVar = this.b;
        WeakHashMap weakHashMap = V.a;
        if (coordinatorLayout.getFitsSystemWindows() && !view.getFitsSystemWindows()) {
            view.setFitsSystemWindows(true);
        }
        if (this.p == null) {
            this.p = new WeakReference(view);
            this.t = new i(view);
            if (gVar != null) {
                view.setBackground(gVar);
                float fE = this.f;
                if (fE == -1.0f) {
                    fE = L.e(view);
                }
                gVar.l(fE);
            } else {
                ColorStateList colorStateList = this.c;
                if (colorStateList != null) {
                    L.i(view, colorStateList);
                }
            }
            int i4 = this.h == 5 ? 4 : 0;
            if (view.getVisibility() != i4) {
                view.setVisibility(i4);
            }
            A();
            if (view.getImportantForAccessibility() == 0) {
                view.setImportantForAccessibility(1);
            }
            if (V.e(view) == null) {
                V.q(view, view.getResources().getString(R.string.side_sheet_accessibility_pane_title));
            }
        }
        int i5 = Gravity.getAbsoluteGravity(((e) view.getLayoutParams()).c, i) == 3 ? 1 : 0;
        a aVar = this.a;
        if (aVar == null || aVar.d() != i5) {
            j jVar = this.d;
            e eVar = null;
            if (i5 == 0) {
                this.a = new a(this, 1);
                if (jVar != null) {
                    WeakReference weakReference = this.p;
                    if (weakReference != null && (view3 = (View) weakReference.get()) != null && (view3.getLayoutParams() instanceof e)) {
                        eVar = (e) view3.getLayoutParams();
                    }
                    if (eVar == null || ((ViewGroup.MarginLayoutParams) eVar).rightMargin <= 0) {
                        G4 g4F = jVar.f();
                        g4F.f = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
                        g4F.g = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
                        j jVarA = g4F.a();
                        if (gVar != null) {
                            gVar.setShapeAppearanceModel(jVarA);
                        }
                    }
                }
            } else {
                if (i5 != 1) {
                    throw new IllegalArgumentException(AbstractC0147y.c(i5, "Invalid sheet edge position value: ", ". Must be 0 or 1."));
                }
                this.a = new a(this, 0);
                if (jVar != null) {
                    WeakReference weakReference2 = this.p;
                    if (weakReference2 != null && (view2 = (View) weakReference2.get()) != null && (view2.getLayoutParams() instanceof e)) {
                        eVar = (e) view2.getLayoutParams();
                    }
                    if (eVar == null || ((ViewGroup.MarginLayoutParams) eVar).leftMargin <= 0) {
                        G4 g4F2 = jVar.f();
                        g4F2.e = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
                        g4F2.h = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
                        j jVarA2 = g4F2.a();
                        if (gVar != null) {
                            gVar.setShapeAppearanceModel(jVarA2);
                        }
                    }
                }
            }
        }
        if (this.i == null) {
            this.i = new androidx.customview.widget.d(coordinatorLayout.getContext(), coordinatorLayout, this.w);
        }
        int iC2 = this.a.c(view);
        coordinatorLayout.r(i, view);
        this.m = coordinatorLayout.getWidth();
        switch (this.a.a) {
            case 0:
                left = coordinatorLayout.getLeft();
                break;
            default:
                left = coordinatorLayout.getRight();
                break;
        }
        this.n = left;
        this.l = view.getWidth();
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
        if (marginLayoutParams != null) {
            switch (this.a.a) {
                case 0:
                    i2 = marginLayoutParams.leftMargin;
                    break;
                default:
                    i2 = marginLayoutParams.rightMargin;
                    break;
            }
        } else {
            i2 = 0;
        }
        this.o = i2;
        int i6 = this.h;
        if (i6 == 1 || i6 == 2) {
            iC = iC2 - this.a.c(view);
        } else if (i6 != 3) {
            if (i6 != 5) {
                throw new IllegalStateException("Unexpected value: " + this.h);
            }
            iC = this.a.b();
        }
        view.offsetLeftAndRight(iC);
        if (this.q == null && (i3 = this.r) != -1 && (viewFindViewById = coordinatorLayout.findViewById(i3)) != null) {
            this.q = new WeakReference(viewFindViewById);
        }
        Iterator it2 = this.v.iterator();
        while (it2.hasNext()) {
            if (it2.next() != null) {
                throw new ClassCastException();
            }
        }
        return true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean m(CoordinatorLayout coordinatorLayout, View view, int i, int i2, int i3) {
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
        view.measure(ViewGroup.getChildMeasureSpec(i, coordinatorLayout.getPaddingRight() + coordinatorLayout.getPaddingLeft() + marginLayoutParams.leftMargin + marginLayoutParams.rightMargin + i2, marginLayoutParams.width), ViewGroup.getChildMeasureSpec(i3, coordinatorLayout.getPaddingBottom() + coordinatorLayout.getPaddingTop() + marginLayoutParams.topMargin + marginLayoutParams.bottomMargin, marginLayoutParams.height));
        return true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void r(View view, Parcelable parcelable) {
        int i = ((SavedState) parcelable).c;
        if (i == 1 || i == 2) {
            i = 5;
        }
        this.h = i;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final Parcelable s(View view) {
        AbsSavedState absSavedState = View.BaseSavedState.EMPTY_STATE;
        return new SavedState(this);
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean v(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        VelocityTracker velocityTracker;
        if (!view.isShown()) {
            return false;
        }
        int actionMasked = motionEvent.getActionMasked();
        if (this.h == 1 && actionMasked == 0) {
            return true;
        }
        if (y()) {
            this.i.j(motionEvent);
        }
        if (actionMasked == 0 && (velocityTracker = this.s) != null) {
            velocityTracker.recycle();
            this.s = null;
        }
        if (this.s == null) {
            this.s = VelocityTracker.obtain();
        }
        this.s.addMovement(motionEvent);
        if (y() && actionMasked == 2 && !this.j && y()) {
            float fAbs = Math.abs(this.u - motionEvent.getX());
            androidx.customview.widget.d dVar = this.i;
            if (fAbs > dVar.b) {
                dVar.b(motionEvent.getPointerId(motionEvent.getActionIndex()), view);
            }
        }
        return !this.j;
    }

    public final void w(int i) {
        if (i == 1 || i == 2) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.t(new StringBuilder("STATE_"), i == 1 ? "DRAGGING" : "SETTLING", " should not be set externally."));
        }
        WeakReference weakReference = this.p;
        if (weakReference == null || weakReference.get() == null) {
            x(i);
            return;
        }
        View view = (View) this.p.get();
        RunnableC0133j runnableC0133j = new RunnableC0133j(this, i, 5);
        ViewParent parent = view.getParent();
        if (parent != null && parent.isLayoutRequested()) {
            WeakHashMap weakHashMap = V.a;
            if (view.isAttachedToWindow()) {
                view.post(runnableC0133j);
                return;
            }
        }
        runnableC0133j.run();
    }

    public final void x(int i) {
        View view;
        if (this.h == i) {
            return;
        }
        this.h = i;
        WeakReference weakReference = this.p;
        if (weakReference == null || (view = (View) weakReference.get()) == null) {
            return;
        }
        int i2 = this.h == 5 ? 4 : 0;
        if (view.getVisibility() != i2) {
            view.setVisibility(i2);
        }
        Iterator it2 = this.v.iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
        A();
    }

    public final boolean y() {
        if (this.i != null) {
            return this.g || this.h == 1;
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x002d, code lost:
    
        if (r1.o(r0, r3.getTop()) != false) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x004b, code lost:
    
        if (r3 != false) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004d, code lost:
    
        x(2);
        r2.e.b(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0056, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void z(android.view.View r3, int r4, boolean r5) {
        /*
            r2 = this;
            r0 = 3
            if (r4 == r0) goto L19
            r0 = 5
            if (r4 != r0) goto Ld
            com.google.android.material.sidesheet.a r0 = r2.a
            int r0 = r0.b()
            goto L1f
        Ld:
            java.lang.IllegalArgumentException r3 = new java.lang.IllegalArgumentException
            java.lang.String r5 = "Invalid state to get outer edge offset: "
            java.lang.String r4 = android.support.v4.media.session.a.f(r4, r5)
            r3.<init>(r4)
            throw r3
        L19:
            com.google.android.material.sidesheet.a r0 = r2.a
            int r0 = r0.a()
        L1f:
            androidx.customview.widget.d r1 = r2.i
            if (r1 == 0) goto L57
            if (r5 == 0) goto L30
            int r3 = r3.getTop()
            boolean r3 = r1.o(r0, r3)
            if (r3 == 0) goto L57
            goto L4d
        L30:
            int r5 = r3.getTop()
            r1.r = r3
            r3 = -1
            r1.c = r3
            r3 = 0
            boolean r3 = r1.h(r0, r5, r3, r3)
            if (r3 != 0) goto L4b
            int r5 = r1.a
            if (r5 != 0) goto L4b
            android.view.View r5 = r1.r
            if (r5 == 0) goto L4b
            r5 = 0
            r1.r = r5
        L4b:
            if (r3 == 0) goto L57
        L4d:
            r3 = 2
            r2.x(r3)
            com.google.android.gms.common.api.internal.k r3 = r2.e
            r3.b(r4)
            return
        L57:
            r2.x(r4)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.sidesheet.SideSheetBehavior.z(android.view.View, int, boolean):void");
    }

    public static class SavedState extends androidx.customview.view.AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new d();
        public final int c;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = parcel.readInt();
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.c);
        }

        public SavedState(SideSheetBehavior sideSheetBehavior) {
            super(AbsSavedState.EMPTY_STATE);
            this.c = sideSheetBehavior.h;
        }
    }

    public SideSheetBehavior(@NonNull Context context, AttributeSet attributeSet) {
        this.e = new k(this);
        this.g = true;
        this.h = 5;
        this.k = 0.1f;
        this.r = -1;
        this.v = new LinkedHashSet();
        this.w = new com.google.android.material.bottomsheet.b(this, 1);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.L);
        if (typedArrayObtainStyledAttributes.hasValue(3)) {
            this.c = AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 3);
        }
        if (typedArrayObtainStyledAttributes.hasValue(6)) {
            this.d = j.b(context, attributeSet, 0, R.style.Widget_Material3_SideSheet).a();
        }
        if (typedArrayObtainStyledAttributes.hasValue(5)) {
            int resourceId = typedArrayObtainStyledAttributes.getResourceId(5, -1);
            this.r = resourceId;
            WeakReference weakReference = this.q;
            if (weakReference != null) {
                weakReference.clear();
            }
            this.q = null;
            WeakReference weakReference2 = this.p;
            if (weakReference2 != null) {
                View view = (View) weakReference2.get();
                if (resourceId != -1) {
                    WeakHashMap weakHashMap = V.a;
                    if (view.isLaidOut()) {
                        view.requestLayout();
                    }
                }
            }
        }
        j jVar = this.d;
        if (jVar != null) {
            g gVar = new g(jVar);
            this.b = gVar;
            gVar.k(context);
            ColorStateList colorStateList = this.c;
            if (colorStateList != null) {
                this.b.m(colorStateList);
            } else {
                TypedValue typedValue = new TypedValue();
                context.getTheme().resolveAttribute(android.R.attr.colorBackground, typedValue, true);
                this.b.setTint(typedValue.data);
            }
        }
        this.f = typedArrayObtainStyledAttributes.getDimension(2, -1.0f);
        this.g = typedArrayObtainStyledAttributes.getBoolean(4, true);
        typedArrayObtainStyledAttributes.recycle();
        ViewConfiguration.get(context).getScaledMaximumFlingVelocity();
    }
}
