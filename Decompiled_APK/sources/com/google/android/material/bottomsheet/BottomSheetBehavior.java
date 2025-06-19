package com.google.android.material.bottomsheet;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Property;
import android.util.SparseIntArray;
import android.util.TypedValue;
import android.view.AbsSavedState;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.activity.C0030b;
import androidx.annotation.NonNull;
import androidx.appcompat.app.K;
import androidx.appcompat.widget.C0076c;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.C1036a;
import androidx.core.view.C1038b;
import androidx.core.view.L;
import androidx.core.view.V;
import com.android.billingclient.api.s;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class BottomSheetBehavior<V extends View> extends androidx.coordinatorlayout.widget.b implements com.google.android.material.motion.b {
    public final k A;
    public final ValueAnimator B;
    public final int C;
    public int D;
    public int E;
    public final float F;
    public int G;
    public final float H;
    public boolean I;
    public boolean J;
    public final boolean K;
    public int L;
    public androidx.customview.widget.d M;
    public boolean V;
    public int W;
    public boolean X;
    public final float Y;
    public int Z;
    public final int a;
    public boolean b;
    public final float c;
    public int c1;
    public final int d;
    public int d1;
    public int e;
    public WeakReference e1;
    public boolean f;
    public WeakReference f1;
    public int g;
    public final ArrayList g1;
    public final int h;
    public VelocityTracker h1;
    public final com.google.android.material.shape.g i;
    public com.google.android.material.motion.f i1;
    public final ColorStateList j;
    public int j1;
    public final int k;
    public int k1;
    public final int l;
    public boolean l1;
    public int m;
    public HashMap m1;
    public final boolean n;
    public final SparseIntArray n1;
    public final boolean o;
    public final b o1;
    public final boolean p;
    public final boolean q;
    public final boolean r;
    public final boolean s;
    public final boolean t;
    public final boolean u;
    public int v;
    public int w;
    public final boolean x;
    public final com.google.android.material.shape.j y;
    public boolean z;

    public BottomSheetBehavior() {
        this.a = 0;
        this.b = true;
        this.k = -1;
        this.l = -1;
        this.A = new k(this);
        this.F = 0.5f;
        this.H = -1.0f;
        this.K = true;
        this.L = 4;
        this.Y = 0.1f;
        this.g1 = new ArrayList();
        this.k1 = -1;
        this.n1 = new SparseIntArray();
        this.o1 = new b(this, 0);
    }

    public static View B(View view) {
        if (view.getVisibility() != 0) {
            return null;
        }
        WeakHashMap weakHashMap = V.a;
        if (L.h(view)) {
            return view;
        }
        if (!(view instanceof ViewGroup)) {
            return null;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View viewB = B(viewGroup.getChildAt(i));
            if (viewB != null) {
                return viewB;
            }
        }
        return null;
    }

    public static BottomSheetBehavior C(View view) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (!(layoutParams instanceof androidx.coordinatorlayout.widget.e)) {
            throw new IllegalArgumentException("The view is not a child of CoordinatorLayout");
        }
        androidx.coordinatorlayout.widget.b bVar = ((androidx.coordinatorlayout.widget.e) layoutParams).a;
        if (bVar instanceof BottomSheetBehavior) {
            return (BottomSheetBehavior) bVar;
        }
        throw new IllegalArgumentException("The view is not associated with BottomSheetBehavior");
    }

    public static int D(int i, int i2, int i3, int i4) {
        int childMeasureSpec = ViewGroup.getChildMeasureSpec(i, i2, i4);
        if (i3 == -1) {
            return childMeasureSpec;
        }
        int mode = View.MeasureSpec.getMode(childMeasureSpec);
        int size = View.MeasureSpec.getSize(childMeasureSpec);
        if (mode == 1073741824) {
            return View.MeasureSpec.makeMeasureSpec(Math.min(size, i3), 1073741824);
        }
        if (size != 0) {
            i3 = Math.min(size, i3);
        }
        return View.MeasureSpec.makeMeasureSpec(i3, Integer.MIN_VALUE);
    }

    public final void A(int i) {
        float f;
        float fE;
        View view = (View) this.e1.get();
        if (view != null) {
            ArrayList arrayList = this.g1;
            if (arrayList.isEmpty()) {
                return;
            }
            int i2 = this.G;
            if (i > i2 || i2 == E()) {
                int i3 = this.G;
                f = i3 - i;
                fE = this.d1 - i3;
            } else {
                int i4 = this.G;
                f = i4 - i;
                fE = i4 - E();
            }
            float f2 = f / fE;
            for (int i5 = 0; i5 < arrayList.size(); i5++) {
                ((c) arrayList.get(i5)).b(view, f2);
            }
        }
    }

    public final int E() {
        if (this.b) {
            return this.D;
        }
        return Math.max(this.C, this.r ? 0 : this.w);
    }

    public final int F(int i) {
        if (i == 3) {
            return E();
        }
        if (i == 4) {
            return this.G;
        }
        if (i == 5) {
            return this.d1;
        }
        if (i == 6) {
            return this.E;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Invalid state to get top offset: "));
    }

    public final boolean G() {
        WeakReference weakReference = this.e1;
        if (weakReference != null && weakReference.get() != null) {
            int[] iArr = new int[2];
            ((View) this.e1.get()).getLocationOnScreen(iArr);
            if (iArr[1] == 0) {
                return true;
            }
        }
        return false;
    }

    public final void H(boolean z) throws Resources.NotFoundException {
        if (this.I != z) {
            this.I = z;
            if (!z && this.L == 5) {
                J(4);
            }
            N();
        }
    }

    public final void I(int i) {
        if (i == -1) {
            if (this.f) {
                return;
            } else {
                this.f = true;
            }
        } else {
            if (!this.f && this.e == i) {
                return;
            }
            this.f = false;
            this.e = Math.max(0, i);
        }
        Q();
    }

    public final void J(int i) {
        if (i == 1 || i == 2) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.t(new StringBuilder("STATE_"), i == 1 ? "DRAGGING" : "SETTLING", " should not be set externally."));
        }
        if (!this.I && i == 5) {
            Log.w("BottomSheetBehavior", "Cannot set state: " + i);
            return;
        }
        int i2 = (i == 6 && this.b && F(i) <= this.D) ? 3 : i;
        WeakReference weakReference = this.e1;
        if (weakReference == null || weakReference.get() == null) {
            K(i);
            return;
        }
        View view = (View) this.e1.get();
        androidx.appcompat.widget.V v = new androidx.appcompat.widget.V(this, view, i2, 5, false);
        ViewParent parent = view.getParent();
        if (parent != null && parent.isLayoutRequested()) {
            WeakHashMap weakHashMap = V.a;
            if (view.isAttachedToWindow()) {
                view.post(v);
                return;
            }
        }
        v.run();
    }

    public final void K(int i) {
        View view;
        if (this.L == i) {
            return;
        }
        this.L = i;
        if (i != 4 && i != 3 && i != 6) {
            boolean z = this.I;
        }
        WeakReference weakReference = this.e1;
        if (weakReference == null || (view = (View) weakReference.get()) == null) {
            return;
        }
        int i2 = 0;
        if (i == 3) {
            P(true);
        } else if (i == 6 || i == 5 || i == 4) {
            P(false);
        }
        O(i, true);
        while (true) {
            ArrayList arrayList = this.g1;
            if (i2 >= arrayList.size()) {
                N();
                return;
            } else {
                ((c) arrayList.get(i2)).c(i, view);
                i2++;
            }
        }
    }

    public final boolean L(View view, float f) {
        if (this.J) {
            return true;
        }
        if (view.getTop() < this.G) {
            return false;
        }
        return Math.abs(((f * this.Y) + ((float) view.getTop())) - ((float) this.G)) / ((float) z()) > 0.5f;
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0030, code lost:
    
        if (r3 != false) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0032, code lost:
    
        K(2);
        O(r4, true);
        r2.A.b(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x003f, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x0012, code lost:
    
        if (r1.o(r3.getLeft(), r0) != false) goto L16;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void M(android.view.View r3, int r4, boolean r5) {
        /*
            r2 = this;
            int r0 = r2.F(r4)
            androidx.customview.widget.d r1 = r2.M
            if (r1 == 0) goto L40
            if (r5 == 0) goto L15
            int r3 = r3.getLeft()
            boolean r3 = r1.o(r3, r0)
            if (r3 == 0) goto L40
            goto L32
        L15:
            int r5 = r3.getLeft()
            r1.r = r3
            r3 = -1
            r1.c = r3
            r3 = 0
            boolean r3 = r1.h(r5, r0, r3, r3)
            if (r3 != 0) goto L30
            int r5 = r1.a
            if (r5 != 0) goto L30
            android.view.View r5 = r1.r
            if (r5 == 0) goto L30
            r5 = 0
            r1.r = r5
        L30:
            if (r3 == 0) goto L40
        L32:
            r3 = 2
            r2.K(r3)
            r3 = 1
            r2.O(r4, r3)
            com.google.android.gms.common.api.internal.k r3 = r2.A
            r3.b(r4)
            return
        L40:
            r2.K(r4)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.bottomsheet.BottomSheetBehavior.M(android.view.View, int, boolean):void");
    }

    public final void N() throws Resources.NotFoundException {
        View view;
        int iA;
        WeakReference weakReference = this.e1;
        if (weakReference == null || (view = (View) weakReference.get()) == null) {
            return;
        }
        V.l(524288, view);
        V.i(0, view);
        V.l(262144, view);
        V.i(0, view);
        V.l(1048576, view);
        V.i(0, view);
        SparseIntArray sparseIntArray = this.n1;
        int i = sparseIntArray.get(0, -1);
        if (i != -1) {
            V.l(i, view);
            V.i(0, view);
            sparseIntArray.delete(0);
        }
        if (!this.b && this.L != 6) {
            String string = view.getResources().getString(R.string.bottomsheet_action_expand_halfway);
            s sVar = new s(this, i, 20);
            ArrayList arrayListF = V.f(view);
            int i2 = 0;
            while (true) {
                if (i2 >= arrayListF.size()) {
                    int i3 = -1;
                    for (int i4 = 0; i4 < 32 && i3 == -1; i4++) {
                        int i5 = V.d[i4];
                        boolean z = true;
                        for (int i6 = 0; i6 < arrayListF.size(); i6++) {
                            z &= ((androidx.core.view.accessibility.d) arrayListF.get(i6)).a() != i5;
                        }
                        if (z) {
                            i3 = i5;
                        }
                    }
                    iA = i3;
                } else {
                    if (TextUtils.equals(string, ((AccessibilityNodeInfo.AccessibilityAction) ((androidx.core.view.accessibility.d) arrayListF.get(i2)).a).getLabel())) {
                        iA = ((androidx.core.view.accessibility.d) arrayListF.get(i2)).a();
                        break;
                    }
                    i2++;
                }
            }
            if (iA != -1) {
                androidx.core.view.accessibility.d dVar = new androidx.core.view.accessibility.d(null, iA, string, sVar, null);
                View.AccessibilityDelegate accessibilityDelegateD = V.d(view);
                C1038b c1038b = accessibilityDelegateD == null ? null : accessibilityDelegateD instanceof C1036a ? ((C1036a) accessibilityDelegateD).a : new C1038b(accessibilityDelegateD);
                if (c1038b == null) {
                    c1038b = new C1038b();
                }
                V.o(view, c1038b);
                V.l(dVar.a(), view);
                V.f(view).add(dVar);
                V.i(0, view);
            }
            sparseIntArray.put(0, iA);
        }
        if (this.I) {
            int i7 = 5;
            if (this.L != 5) {
                V.m(view, androidx.core.view.accessibility.d.l, new s(this, i7, 20));
            }
        }
        int i8 = this.L;
        int i9 = 4;
        int i10 = 3;
        if (i8 == 3) {
            V.m(view, androidx.core.view.accessibility.d.k, new s(this, this.b ? 4 : 6, 20));
            return;
        }
        if (i8 == 4) {
            V.m(view, androidx.core.view.accessibility.d.j, new s(this, this.b ? 3 : 6, 20));
        } else {
            if (i8 != 6) {
                return;
            }
            V.m(view, androidx.core.view.accessibility.d.k, new s(this, i9, 20));
            V.m(view, androidx.core.view.accessibility.d.j, new s(this, i10, 20));
        }
    }

    public final void O(int i, boolean z) {
        com.google.android.material.shape.g gVar = this.i;
        ValueAnimator valueAnimator = this.B;
        if (i == 2) {
            return;
        }
        boolean z2 = this.L == 3 && (this.x || G());
        if (this.z == z2 || gVar == null) {
            return;
        }
        this.z = z2;
        if (!z || valueAnimator == null) {
            if (valueAnimator != null && valueAnimator.isRunning()) {
                valueAnimator.cancel();
            }
            gVar.n(this.z ? y() : 1.0f);
            return;
        }
        if (valueAnimator.isRunning()) {
            valueAnimator.reverse();
        } else {
            valueAnimator.setFloatValues(gVar.a.i, z2 ? y() : 1.0f);
            valueAnimator.start();
        }
    }

    public final void P(boolean z) {
        WeakReference weakReference = this.e1;
        if (weakReference == null) {
            return;
        }
        ViewParent parent = ((View) weakReference.get()).getParent();
        if (parent instanceof CoordinatorLayout) {
            CoordinatorLayout coordinatorLayout = (CoordinatorLayout) parent;
            int childCount = coordinatorLayout.getChildCount();
            if (z) {
                if (this.m1 != null) {
                    return;
                } else {
                    this.m1 = new HashMap(childCount);
                }
            }
            for (int i = 0; i < childCount; i++) {
                View childAt = coordinatorLayout.getChildAt(i);
                if (childAt != this.e1.get() && z) {
                    this.m1.put(childAt, Integer.valueOf(childAt.getImportantForAccessibility()));
                }
            }
            if (z) {
                return;
            }
            this.m1 = null;
        }
    }

    public final void Q() {
        View view;
        if (this.e1 != null) {
            x();
            if (this.L != 4 || (view = (View) this.e1.get()) == null) {
                return;
            }
            view.requestLayout();
        }
    }

    @Override // com.google.android.material.motion.b
    public final void a(C0030b c0030b) {
        com.google.android.material.motion.f fVar = this.i1;
        if (fVar == null) {
            return;
        }
        fVar.f = c0030b;
    }

    @Override // com.google.android.material.motion.b
    public final void b(C0030b c0030b) {
        com.google.android.material.motion.f fVar = this.i1;
        if (fVar == null) {
            return;
        }
        if (fVar.f == null) {
            Log.w("MaterialBackHelper", "Must call startBackProgress() before updateBackProgress()");
        }
        C0030b c0030b2 = fVar.f;
        fVar.f = c0030b;
        if (c0030b2 == null) {
            return;
        }
        fVar.c(c0030b.c);
    }

    @Override // com.google.android.material.motion.b
    public final void c() {
        com.google.android.material.motion.f fVar = this.i1;
        if (fVar == null) {
            return;
        }
        C0030b c0030b = fVar.f;
        fVar.f = null;
        if (c0030b == null || Build.VERSION.SDK_INT < 34) {
            J(this.I ? 5 : 4);
            return;
        }
        boolean z = this.I;
        int i = fVar.d;
        int i2 = fVar.c;
        float f = c0030b.c;
        if (!z) {
            AnimatorSet animatorSetB = fVar.b();
            animatorSetB.setDuration(com.google.android.material.animation.a.c(i2, f, i));
            animatorSetB.start();
            J(4);
            return;
        }
        C0076c c0076c = new C0076c(this, 5);
        View view = fVar.b;
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(view, (Property<View, Float>) View.TRANSLATION_Y, view.getScaleY() * view.getHeight());
        objectAnimatorOfFloat.setInterpolator(new androidx.interpolator.view.animation.a(1));
        objectAnimatorOfFloat.setDuration(com.google.android.material.animation.a.c(i2, f, i));
        objectAnimatorOfFloat.addListener(new C0076c(fVar, 8));
        objectAnimatorOfFloat.addListener(c0076c);
        objectAnimatorOfFloat.start();
    }

    @Override // com.google.android.material.motion.b
    public final void d() {
        com.google.android.material.motion.f fVar = this.i1;
        if (fVar == null || fVar.a() == null) {
            return;
        }
        AnimatorSet animatorSetB = fVar.b();
        animatorSetB.setDuration(fVar.e);
        animatorSetB.start();
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void g(androidx.coordinatorlayout.widget.e eVar) {
        this.e1 = null;
        this.M = null;
        this.i1 = null;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void j() {
        this.e1 = null;
        this.M = null;
        this.i1 = null;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean k(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        int i;
        androidx.customview.widget.d dVar;
        if (!view.isShown() || !this.K) {
            this.V = true;
            return false;
        }
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0) {
            this.j1 = -1;
            this.k1 = -1;
            VelocityTracker velocityTracker = this.h1;
            if (velocityTracker != null) {
                velocityTracker.recycle();
                this.h1 = null;
            }
        }
        if (this.h1 == null) {
            this.h1 = VelocityTracker.obtain();
        }
        this.h1.addMovement(motionEvent);
        if (actionMasked == 0) {
            int x = (int) motionEvent.getX();
            this.k1 = (int) motionEvent.getY();
            if (this.L != 2) {
                WeakReference weakReference = this.f1;
                View view2 = weakReference != null ? (View) weakReference.get() : null;
                if (view2 != null && coordinatorLayout.p(view2, x, this.k1)) {
                    this.j1 = motionEvent.getPointerId(motionEvent.getActionIndex());
                    this.l1 = true;
                }
            }
            this.V = this.j1 == -1 && !coordinatorLayout.p(view, x, this.k1);
        } else if (actionMasked == 1 || actionMasked == 3) {
            this.l1 = false;
            this.j1 = -1;
            if (this.V) {
                this.V = false;
                return false;
            }
        }
        if (this.V || (dVar = this.M) == null || !dVar.p(motionEvent)) {
            WeakReference weakReference2 = this.f1;
            View view3 = weakReference2 != null ? (View) weakReference2.get() : null;
            if (actionMasked != 2 || view3 == null || this.V || this.L == 1 || coordinatorLayout.p(view3, (int) motionEvent.getX(), (int) motionEvent.getY()) || this.M == null || (i = this.k1) == -1 || Math.abs(i - motionEvent.getY()) <= this.M.b) {
                return false;
            }
        }
        return true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) throws Resources.NotFoundException {
        int i2 = this.l;
        com.google.android.material.shape.g gVar = this.i;
        WeakHashMap weakHashMap = V.a;
        if (coordinatorLayout.getFitsSystemWindows() && !view.getFitsSystemWindows()) {
            view.setFitsSystemWindows(true);
        }
        int i3 = 0;
        if (this.e1 == null) {
            this.g = coordinatorLayout.getResources().getDimensionPixelSize(R.dimen.design_bottom_sheet_peek_height_min);
            boolean z = (Build.VERSION.SDK_INT < 29 || this.n || this.f) ? false : true;
            if (this.o || this.p || this.q || this.s || this.t || this.u || z) {
                p.f(view, new K(this, z));
            }
            V.r(view, new j(view));
            this.e1 = new WeakReference(view);
            this.i1 = new com.google.android.material.motion.f(view);
            if (gVar != null) {
                view.setBackground(gVar);
                float fE = this.H;
                if (fE == -1.0f) {
                    fE = L.e(view);
                }
                gVar.l(fE);
            } else {
                ColorStateList colorStateList = this.j;
                if (colorStateList != null) {
                    L.i(view, colorStateList);
                }
            }
            N();
            if (view.getImportantForAccessibility() == 0) {
                view.setImportantForAccessibility(1);
            }
        }
        if (this.M == null) {
            this.M = new androidx.customview.widget.d(coordinatorLayout.getContext(), coordinatorLayout, this.o1);
        }
        int top = view.getTop();
        coordinatorLayout.r(i, view);
        this.c1 = coordinatorLayout.getWidth();
        this.d1 = coordinatorLayout.getHeight();
        int height = view.getHeight();
        this.Z = height;
        int iMin = this.d1;
        int i4 = iMin - height;
        int i5 = this.w;
        if (i4 < i5) {
            if (this.r) {
                if (i2 != -1) {
                    iMin = Math.min(iMin, i2);
                }
                this.Z = iMin;
            } else {
                int iMin2 = iMin - i5;
                if (i2 != -1) {
                    iMin2 = Math.min(iMin2, i2);
                }
                this.Z = iMin2;
            }
        }
        this.D = Math.max(0, this.d1 - this.Z);
        this.E = (int) ((1.0f - this.F) * this.d1);
        x();
        int i6 = this.L;
        if (i6 == 3) {
            view.offsetTopAndBottom(E());
        } else if (i6 == 6) {
            view.offsetTopAndBottom(this.E);
        } else if (this.I && i6 == 5) {
            view.offsetTopAndBottom(this.d1);
        } else if (i6 == 4) {
            view.offsetTopAndBottom(this.G);
        } else if (i6 == 1 || i6 == 2) {
            view.offsetTopAndBottom(top - view.getTop());
        }
        O(this.L, false);
        this.f1 = new WeakReference(B(view));
        while (true) {
            ArrayList arrayList = this.g1;
            if (i3 >= arrayList.size()) {
                return true;
            }
            ((c) arrayList.get(i3)).a(view);
            i3++;
        }
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean m(CoordinatorLayout coordinatorLayout, View view, int i, int i2, int i3) {
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
        view.measure(D(i, coordinatorLayout.getPaddingRight() + coordinatorLayout.getPaddingLeft() + marginLayoutParams.leftMargin + marginLayoutParams.rightMargin + i2, this.k, marginLayoutParams.width), D(i3, coordinatorLayout.getPaddingBottom() + coordinatorLayout.getPaddingTop() + marginLayoutParams.topMargin + marginLayoutParams.bottomMargin, this.l, marginLayoutParams.height));
        return true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean n(CoordinatorLayout coordinatorLayout, View view, View view2, float f, float f2) {
        WeakReference weakReference = this.f1;
        return (weakReference == null || view2 != weakReference.get() || this.L == 3) ? false : true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public void o(CoordinatorLayout coordinatorLayout, View view, View view2, int i, int i2, int[] iArr, int i3) {
        boolean z = this.K;
        if (i3 == 1) {
            return;
        }
        WeakReference weakReference = this.f1;
        if (view2 != (weakReference != null ? (View) weakReference.get() : null)) {
            return;
        }
        int top = view.getTop();
        int i4 = top - i2;
        if (i2 > 0) {
            if (i4 < E()) {
                int iE = top - E();
                iArr[1] = iE;
                WeakHashMap weakHashMap = V.a;
                view.offsetTopAndBottom(-iE);
                K(3);
            } else {
                if (!z) {
                    return;
                }
                iArr[1] = i2;
                WeakHashMap weakHashMap2 = V.a;
                view.offsetTopAndBottom(-i2);
                K(1);
            }
        } else if (i2 < 0 && !view2.canScrollVertically(-1)) {
            int i5 = this.G;
            if (i4 > i5 && !this.I) {
                int i6 = top - i5;
                iArr[1] = i6;
                WeakHashMap weakHashMap3 = V.a;
                view.offsetTopAndBottom(-i6);
                K(4);
            } else {
                if (!z) {
                    return;
                }
                iArr[1] = i2;
                WeakHashMap weakHashMap4 = V.a;
                view.offsetTopAndBottom(-i2);
                K(1);
            }
        }
        A(view.getTop());
        this.W = i2;
        this.X = true;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void p(CoordinatorLayout coordinatorLayout, View view, int i, int i2, int i3, int[] iArr) {
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void r(View view, Parcelable parcelable) {
        SavedState savedState = (SavedState) parcelable;
        int i = this.a;
        if (i != 0) {
            if (i == -1 || (i & 1) == 1) {
                this.e = savedState.d;
            }
            if (i == -1 || (i & 2) == 2) {
                this.b = savedState.e;
            }
            if (i == -1 || (i & 4) == 4) {
                this.I = savedState.f;
            }
            if (i == -1 || (i & 8) == 8) {
                this.J = savedState.g;
            }
        }
        int i2 = savedState.c;
        if (i2 == 1 || i2 == 2) {
            this.L = 4;
        } else {
            this.L = i2;
        }
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final Parcelable s(View view) {
        AbsSavedState absSavedState = View.BaseSavedState.EMPTY_STATE;
        return new SavedState(this);
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean t(CoordinatorLayout coordinatorLayout, View view, View view2, View view3, int i, int i2) {
        this.W = 0;
        this.X = false;
        return (i & 2) != 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00ae  */
    @Override // androidx.coordinatorlayout.widget.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void u(androidx.coordinatorlayout.widget.CoordinatorLayout r3, android.view.View r4, android.view.View r5, int r6) {
        /*
            r2 = this;
            int r3 = r4.getTop()
            int r6 = r2.E()
            r0 = 3
            if (r3 != r6) goto Lf
            r2.K(r0)
            return
        Lf:
            java.lang.ref.WeakReference r3 = r2.f1
            if (r3 == 0) goto Lb5
            java.lang.Object r3 = r3.get()
            if (r5 != r3) goto Lb5
            boolean r3 = r2.X
            if (r3 != 0) goto L1f
            goto Lb5
        L1f:
            int r3 = r2.W
            r5 = 6
            if (r3 <= 0) goto L34
            boolean r3 = r2.b
            if (r3 == 0) goto L2a
            goto Laf
        L2a:
            int r3 = r4.getTop()
            int r6 = r2.E
            if (r3 <= r6) goto Laf
            goto Lae
        L34:
            boolean r3 = r2.I
            if (r3 == 0) goto L55
            android.view.VelocityTracker r3 = r2.h1
            if (r3 != 0) goto L3e
            r3 = 0
            goto L4d
        L3e:
            r6 = 1000(0x3e8, float:1.401E-42)
            float r1 = r2.c
            r3.computeCurrentVelocity(r6, r1)
            android.view.VelocityTracker r3 = r2.h1
            int r6 = r2.j1
            float r3 = r3.getYVelocity(r6)
        L4d:
            boolean r3 = r2.L(r4, r3)
            if (r3 == 0) goto L55
            r0 = 5
            goto Laf
        L55:
            int r3 = r2.W
            r6 = 4
            if (r3 != 0) goto L93
            int r3 = r4.getTop()
            boolean r1 = r2.b
            if (r1 == 0) goto L74
            int r5 = r2.D
            int r5 = r3 - r5
            int r5 = java.lang.Math.abs(r5)
            int r1 = r2.G
            int r3 = r3 - r1
            int r3 = java.lang.Math.abs(r3)
            if (r5 >= r3) goto L97
            goto Laf
        L74:
            int r1 = r2.E
            if (r3 >= r1) goto L83
            int r6 = r2.G
            int r6 = r3 - r6
            int r6 = java.lang.Math.abs(r6)
            if (r3 >= r6) goto Lae
            goto Laf
        L83:
            int r0 = r3 - r1
            int r0 = java.lang.Math.abs(r0)
            int r1 = r2.G
            int r3 = r3 - r1
            int r3 = java.lang.Math.abs(r3)
            if (r0 >= r3) goto L97
            goto Lae
        L93:
            boolean r3 = r2.b
            if (r3 == 0) goto L99
        L97:
            r0 = r6
            goto Laf
        L99:
            int r3 = r4.getTop()
            int r0 = r2.E
            int r0 = r3 - r0
            int r0 = java.lang.Math.abs(r0)
            int r1 = r2.G
            int r3 = r3 - r1
            int r3 = java.lang.Math.abs(r3)
            if (r0 >= r3) goto L97
        Lae:
            r0 = r5
        Laf:
            r3 = 0
            r2.M(r4, r0, r3)
            r2.X = r3
        Lb5:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.bottomsheet.BottomSheetBehavior.u(androidx.coordinatorlayout.widget.CoordinatorLayout, android.view.View, android.view.View, int):void");
    }

    @Override // androidx.coordinatorlayout.widget.b
    public boolean v(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        if (!view.isShown()) {
            return false;
        }
        int actionMasked = motionEvent.getActionMasked();
        int i = this.L;
        if (i == 1 && actionMasked == 0) {
            return true;
        }
        androidx.customview.widget.d dVar = this.M;
        if (dVar != null && (this.K || i == 1)) {
            dVar.j(motionEvent);
        }
        if (actionMasked == 0) {
            this.j1 = -1;
            this.k1 = -1;
            VelocityTracker velocityTracker = this.h1;
            if (velocityTracker != null) {
                velocityTracker.recycle();
                this.h1 = null;
            }
        }
        if (this.h1 == null) {
            this.h1 = VelocityTracker.obtain();
        }
        this.h1.addMovement(motionEvent);
        if (this.M != null && ((this.K || this.L == 1) && actionMasked == 2 && !this.V)) {
            float fAbs = Math.abs(this.k1 - motionEvent.getY());
            androidx.customview.widget.d dVar2 = this.M;
            if (fAbs > dVar2.b) {
                dVar2.b(motionEvent.getPointerId(motionEvent.getActionIndex()), view);
            }
        }
        return !this.V;
    }

    public final void w(c cVar) {
        ArrayList arrayList = this.g1;
        if (arrayList.contains(cVar)) {
            return;
        }
        arrayList.add(cVar);
    }

    public final void x() {
        int iZ = z();
        if (this.b) {
            this.G = Math.max(this.d1 - iZ, this.D);
        } else {
            this.G = this.d1 - iZ;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0044  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final float y() {
        /*
            r5 = this;
            com.google.android.material.shape.g r0 = r5.i
            r1 = 0
            if (r0 == 0) goto L6f
            java.lang.ref.WeakReference r0 = r5.e1
            if (r0 == 0) goto L6f
            java.lang.Object r0 = r0.get()
            if (r0 == 0) goto L6f
            int r0 = android.os.Build.VERSION.SDK_INT
            r2 = 31
            if (r0 < r2) goto L6f
            java.lang.ref.WeakReference r0 = r5.e1
            java.lang.Object r0 = r0.get()
            android.view.View r0 = (android.view.View) r0
            boolean r2 = r5.G()
            if (r2 == 0) goto L6f
            android.view.WindowInsets r0 = r0.getRootWindowInsets()
            if (r0 == 0) goto L6f
            com.google.android.material.shape.g r2 = r5.i
            float r2 = r2.i()
            android.view.RoundedCorner r3 = com.google.android.gms.internal.ads.AbstractC1830aE.p(r0)
            if (r3 == 0) goto L44
            int r3 = com.google.android.material.bottomsheet.a.a(r3)
            float r3 = (float) r3
            int r4 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r4 <= 0) goto L44
            int r4 = (r2 > r1 ? 1 : (r2 == r1 ? 0 : -1))
            if (r4 <= 0) goto L44
            float r3 = r3 / r2
            goto L45
        L44:
            r3 = r1
        L45:
            com.google.android.material.shape.g r2 = r5.i
            com.google.android.material.shape.f r4 = r2.a
            com.google.android.material.shape.j r4 = r4.a
            com.google.android.material.shape.c r4 = r4.f
            android.graphics.RectF r2 = r2.g()
            float r2 = r4.a(r2)
            android.view.RoundedCorner r0 = com.google.android.gms.internal.ads.AbstractC1830aE.B(r0)
            if (r0 == 0) goto L6a
            int r0 = com.google.android.material.bottomsheet.a.a(r0)
            float r0 = (float) r0
            int r4 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            if (r4 <= 0) goto L6a
            int r4 = (r2 > r1 ? 1 : (r2 == r1 ? 0 : -1))
            if (r4 <= 0) goto L6a
            float r1 = r0 / r2
        L6a:
            float r0 = java.lang.Math.max(r3, r1)
            return r0
        L6f:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.bottomsheet.BottomSheetBehavior.y():float");
    }

    public final int z() {
        int i;
        return this.f ? Math.min(Math.max(this.g, this.d1 - ((this.c1 * 9) / 16)), this.Z) + this.v : (this.n || this.o || (i = this.m) <= 0) ? this.e + this.v : Math.max(this.e, i + this.h);
    }

    public static class SavedState extends androidx.customview.view.AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new d();
        public final int c;
        public final int d;
        public final boolean e;
        public final boolean f;
        public final boolean g;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = parcel.readInt();
            this.d = parcel.readInt();
            this.e = parcel.readInt() == 1;
            this.f = parcel.readInt() == 1;
            this.g = parcel.readInt() == 1;
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.c);
            parcel.writeInt(this.d);
            parcel.writeInt(this.e ? 1 : 0);
            parcel.writeInt(this.f ? 1 : 0);
            parcel.writeInt(this.g ? 1 : 0);
        }

        public SavedState(BottomSheetBehavior bottomSheetBehavior) {
            super(AbsSavedState.EMPTY_STATE);
            this.c = bottomSheetBehavior.L;
            this.d = bottomSheetBehavior.e;
            this.e = bottomSheetBehavior.b;
            this.f = bottomSheetBehavior.I;
            this.g = bottomSheetBehavior.J;
        }
    }

    public BottomSheetBehavior(@NonNull Context context, AttributeSet attributeSet) throws Resources.NotFoundException {
        int i;
        this.a = 0;
        this.b = true;
        this.k = -1;
        this.l = -1;
        this.A = new k(this);
        this.F = 0.5f;
        this.H = -1.0f;
        this.K = true;
        this.L = 4;
        this.Y = 0.1f;
        this.g1 = new ArrayList();
        this.k1 = -1;
        this.n1 = new SparseIntArray();
        this.o1 = new b(this, 0);
        this.h = context.getResources().getDimensionPixelSize(R.dimen.mtrl_min_touch_target_size);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.e);
        if (typedArrayObtainStyledAttributes.hasValue(3)) {
            this.j = AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 3);
        }
        if (typedArrayObtainStyledAttributes.hasValue(21)) {
            this.y = com.google.android.material.shape.j.b(context, attributeSet, R.attr.bottomSheetStyle, R.style.Widget_Design_BottomSheet_Modal).a();
        }
        com.google.android.material.shape.j jVar = this.y;
        if (jVar != null) {
            com.google.android.material.shape.g gVar = new com.google.android.material.shape.g(jVar);
            this.i = gVar;
            gVar.k(context);
            ColorStateList colorStateList = this.j;
            if (colorStateList != null) {
                this.i.m(colorStateList);
            } else {
                TypedValue typedValue = new TypedValue();
                context.getTheme().resolveAttribute(android.R.attr.colorBackground, typedValue, true);
                this.i.setTint(typedValue.data);
            }
        }
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(y(), 1.0f);
        this.B = valueAnimatorOfFloat;
        valueAnimatorOfFloat.setDuration(500L);
        this.B.addUpdateListener(new com.google.android.material.appbar.g(this, 1));
        this.H = typedArrayObtainStyledAttributes.getDimension(2, -1.0f);
        if (typedArrayObtainStyledAttributes.hasValue(0)) {
            this.k = typedArrayObtainStyledAttributes.getDimensionPixelSize(0, -1);
        }
        if (typedArrayObtainStyledAttributes.hasValue(1)) {
            this.l = typedArrayObtainStyledAttributes.getDimensionPixelSize(1, -1);
        }
        TypedValue typedValuePeekValue = typedArrayObtainStyledAttributes.peekValue(9);
        if (typedValuePeekValue != null && (i = typedValuePeekValue.data) == -1) {
            I(i);
        } else {
            I(typedArrayObtainStyledAttributes.getDimensionPixelSize(9, -1));
        }
        H(typedArrayObtainStyledAttributes.getBoolean(8, false));
        this.n = typedArrayObtainStyledAttributes.getBoolean(13, false);
        boolean z = typedArrayObtainStyledAttributes.getBoolean(6, true);
        if (this.b != z) {
            this.b = z;
            if (this.e1 != null) {
                x();
            }
            K((this.b && this.L == 6) ? 3 : this.L);
            O(this.L, true);
            N();
        }
        this.J = typedArrayObtainStyledAttributes.getBoolean(12, false);
        this.K = typedArrayObtainStyledAttributes.getBoolean(4, true);
        this.a = typedArrayObtainStyledAttributes.getInt(10, 0);
        float f = typedArrayObtainStyledAttributes.getFloat(7, 0.5f);
        if (f > DefinitionKt.NO_Float_VALUE && f < 1.0f) {
            this.F = f;
            if (this.e1 != null) {
                this.E = (int) ((1.0f - f) * this.d1);
            }
            TypedValue typedValuePeekValue2 = typedArrayObtainStyledAttributes.peekValue(5);
            if (typedValuePeekValue2 != null && typedValuePeekValue2.type == 16) {
                int i2 = typedValuePeekValue2.data;
                if (i2 >= 0) {
                    this.C = i2;
                    O(this.L, true);
                } else {
                    throw new IllegalArgumentException("offset must be greater than or equal to 0");
                }
            } else {
                int dimensionPixelOffset = typedArrayObtainStyledAttributes.getDimensionPixelOffset(5, 0);
                if (dimensionPixelOffset >= 0) {
                    this.C = dimensionPixelOffset;
                    O(this.L, true);
                } else {
                    throw new IllegalArgumentException("offset must be greater than or equal to 0");
                }
            }
            this.d = typedArrayObtainStyledAttributes.getInt(11, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
            this.o = typedArrayObtainStyledAttributes.getBoolean(17, false);
            this.p = typedArrayObtainStyledAttributes.getBoolean(18, false);
            this.q = typedArrayObtainStyledAttributes.getBoolean(19, false);
            this.r = typedArrayObtainStyledAttributes.getBoolean(20, true);
            this.s = typedArrayObtainStyledAttributes.getBoolean(14, false);
            this.t = typedArrayObtainStyledAttributes.getBoolean(15, false);
            this.u = typedArrayObtainStyledAttributes.getBoolean(16, false);
            this.x = typedArrayObtainStyledAttributes.getBoolean(23, true);
            typedArrayObtainStyledAttributes.recycle();
            this.c = ViewConfiguration.get(context).getScaledMaximumFlingVelocity();
            return;
        }
        throw new IllegalArgumentException("ratio must be a float value between 0 and 1");
    }
}
