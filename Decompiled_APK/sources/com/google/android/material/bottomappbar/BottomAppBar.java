package com.google.android.material.bottomappbar;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.appcompat.app.L;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.t1;
import androidx.collection.V;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.RunnableC1068z;
import androidx.customview.view.AbsSavedState;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.material.behavior.HideBottomViewOnScrollBehavior;
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.internal.p;
import com.google.android.material.internal.q;
import com.google.android.material.shape.i;
import com.google.android.material.shape.j;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class BottomAppBar extends Toolbar implements androidx.coordinatorlayout.widget.a {
    public static final /* synthetic */ int E1 = 0;
    public int A1;
    public int B1;
    public final a C1;
    public final com.google.firebase.platforminfo.c D1;
    public Integer h1;
    public final com.google.android.material.shape.g i1;
    public AnimatorSet j1;
    public AnimatorSet k1;
    public int l1;
    public int m1;
    public int n1;
    public final int o1;
    public int p1;
    public int q1;
    public final boolean r1;
    public boolean s1;
    public final boolean t1;
    public final boolean u1;
    public final boolean v1;
    public boolean w1;
    public boolean x1;
    public Behavior y1;
    public int z1;

    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new f();
        public int c;
        public boolean d;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = parcel.readInt();
            this.d = parcel.readInt() != 0;
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.c);
            parcel.writeInt(this.d ? 1 : 0);
        }
    }

    public BottomAppBar(@NonNull Context context) {
        super(com.google.android.material.theme.overlay.a.a(context, null, R.attr.bottomAppBarStyle, R.style.Widget_MaterialComponents_BottomAppBar), null, R.attr.bottomAppBarStyle);
        com.google.android.material.shape.g gVar = new com.google.android.material.shape.g();
        this.i1 = gVar;
        this.w1 = false;
        this.x1 = true;
        this.C1 = new a(this, 0);
        this.D1 = new com.google.firebase.platforminfo.c(this);
        Context context2 = getContext();
        TypedArray typedArrayL = p.l(context2, null, com.google.android.material.a.d, R.attr.bottomAppBarStyle, R.style.Widget_MaterialComponents_BottomAppBar, new int[0]);
        ColorStateList colorStateListA = AbstractC3442d4.a(context2, typedArrayL, 1);
        if (typedArrayL.hasValue(12)) {
            setNavigationIconTint(typedArrayL.getColor(12, -1));
        }
        int dimensionPixelSize = typedArrayL.getDimensionPixelSize(2, 0);
        float dimensionPixelOffset = typedArrayL.getDimensionPixelOffset(7, 0);
        float dimensionPixelOffset2 = typedArrayL.getDimensionPixelOffset(8, 0);
        float dimensionPixelOffset3 = typedArrayL.getDimensionPixelOffset(9, 0);
        this.l1 = typedArrayL.getInt(3, 0);
        this.m1 = typedArrayL.getInt(6, 0);
        this.n1 = typedArrayL.getInt(5, 1);
        this.r1 = typedArrayL.getBoolean(16, true);
        this.q1 = typedArrayL.getInt(11, 0);
        this.s1 = typedArrayL.getBoolean(10, false);
        this.t1 = typedArrayL.getBoolean(13, false);
        this.u1 = typedArrayL.getBoolean(14, false);
        this.v1 = typedArrayL.getBoolean(15, false);
        this.p1 = typedArrayL.getDimensionPixelOffset(4, -1);
        boolean z = typedArrayL.getBoolean(0, true);
        typedArrayL.recycle();
        this.o1 = getResources().getDimensionPixelOffset(R.dimen.mtrl_bottomappbar_fabOffsetEndMode);
        g gVar2 = new g(0);
        gVar2.g = -1.0f;
        gVar2.c = dimensionPixelOffset;
        gVar2.b = dimensionPixelOffset2;
        gVar2.y(dimensionPixelOffset3);
        gVar2.f = DefinitionKt.NO_Float_VALUE;
        i iVar = new i();
        i iVar2 = new i();
        i iVar3 = new i();
        i iVar4 = new i();
        com.google.android.material.shape.a aVar = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
        com.google.android.material.shape.a aVar2 = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
        com.google.android.material.shape.a aVar3 = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
        com.google.android.material.shape.a aVar4 = new com.google.android.material.shape.a(DefinitionKt.NO_Float_VALUE);
        com.google.android.material.shape.e eVar = new com.google.android.material.shape.e(0);
        com.google.android.material.shape.e eVar2 = new com.google.android.material.shape.e(0);
        com.google.android.material.shape.e eVar3 = new com.google.android.material.shape.e(0);
        j jVar = new j();
        jVar.a = iVar;
        jVar.b = iVar2;
        jVar.c = iVar3;
        jVar.d = iVar4;
        jVar.e = aVar;
        jVar.f = aVar2;
        jVar.g = aVar3;
        jVar.h = aVar4;
        jVar.i = gVar2;
        jVar.j = eVar;
        jVar.k = eVar2;
        jVar.l = eVar3;
        gVar.setShapeAppearanceModel(jVar);
        if (z) {
            gVar.q(2);
        } else {
            gVar.q(1);
            if (Build.VERSION.SDK_INT >= 28) {
                setOutlineAmbientShadowColor(0);
                setOutlineSpotShadowColor(0);
            }
        }
        Paint.Style style = Paint.Style.FILL;
        gVar.o();
        gVar.k(context2);
        setElevation(dimensionPixelSize);
        gVar.setTintList(colorStateListA);
        setBackground(gVar);
        L l = new L(this, 25);
        TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(null, com.google.android.material.a.t, R.attr.bottomAppBarStyle, R.style.Widget_MaterialComponents_BottomAppBar);
        boolean z2 = typedArrayObtainStyledAttributes.getBoolean(3, false);
        boolean z3 = typedArrayObtainStyledAttributes.getBoolean(4, false);
        boolean z4 = typedArrayObtainStyledAttributes.getBoolean(5, false);
        typedArrayObtainStyledAttributes.recycle();
        q qVar = new q();
        qVar.a = z2;
        qVar.b = z3;
        qVar.c = z4;
        qVar.d = l;
        p.f(this, qVar);
    }

    public static void L(BottomAppBar bottomAppBar, View view) {
        androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) view.getLayoutParams();
        eVar.d = 17;
        int i = bottomAppBar.n1;
        if (i == 1) {
            eVar.d = 49;
        }
        if (i == 0) {
            eVar.d |= 80;
        }
    }

    private ActionMenuView getActionMenuView() {
        for (int i = 0; i < getChildCount(); i++) {
            View childAt = getChildAt(i);
            if (childAt instanceof ActionMenuView) {
                return (ActionMenuView) childAt;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getBottomInset() {
        return this.z1;
    }

    private int getFabAlignmentAnimationDuration() {
        return AbstractC3430b4.d(getContext(), R.attr.motionDurationLong2, 300);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getFabTranslationX() {
        return E(this.l1);
    }

    private float getFabTranslationY() {
        if (this.n1 == 1) {
            return -getTopEdgeTreatment().e;
        }
        return C() != null ? (-((getMeasuredHeight() + getBottomInset()) - r0.getMeasuredHeight())) / 2 : 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getLeftInset() {
        return this.B1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getRightInset() {
        return this.A1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NonNull
    public g getTopEdgeTreatment() {
        return (g) this.i1.a.a.i;
    }

    public final View C() {
        if (!(getParent() instanceof CoordinatorLayout)) {
            return null;
        }
        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) getParent();
        List list = (List) ((V) coordinatorLayout.b.b).get(this);
        ArrayList arrayList = coordinatorLayout.d;
        arrayList.clear();
        if (list != null) {
            arrayList.addAll(list);
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            View view = (View) it2.next();
            if ((view instanceof FloatingActionButton) || (view instanceof ExtendedFloatingActionButton)) {
                return view;
            }
        }
        return null;
    }

    public final int D(ActionMenuView actionMenuView, int i, boolean z) throws Resources.NotFoundException {
        int dimensionPixelOffset = 0;
        if (this.q1 != 1 && (i != 1 || !z)) {
            return 0;
        }
        boolean zK = p.k(this);
        int measuredWidth = zK ? getMeasuredWidth() : 0;
        for (int i2 = 0; i2 < getChildCount(); i2++) {
            View childAt = getChildAt(i2);
            if ((childAt.getLayoutParams() instanceof t1) && (((t1) childAt.getLayoutParams()).a & 8388615) == 8388611) {
                measuredWidth = zK ? Math.min(measuredWidth, childAt.getLeft()) : Math.max(measuredWidth, childAt.getRight());
            }
        }
        int right = zK ? actionMenuView.getRight() : actionMenuView.getLeft();
        int i3 = zK ? this.A1 : -this.B1;
        if (getNavigationIcon() == null) {
            dimensionPixelOffset = getResources().getDimensionPixelOffset(R.dimen.m3_bottomappbar_horizontal_padding);
            if (!zK) {
                dimensionPixelOffset = -dimensionPixelOffset;
            }
        }
        return measuredWidth - ((right + i3) + dimensionPixelOffset);
    }

    public final float E(int i) {
        boolean zK = p.k(this);
        if (i != 1) {
            return DefinitionKt.NO_Float_VALUE;
        }
        View viewC = C();
        int i2 = zK ? this.B1 : this.A1;
        return ((getMeasuredWidth() / 2) - ((this.p1 == -1 || viewC == null) ? this.o1 + i2 : ((viewC.getMeasuredWidth() / 2) + this.p1) + i2)) * (zK ? -1 : 1);
    }

    public final boolean F() {
        View viewC = C();
        FloatingActionButton floatingActionButton = viewC instanceof FloatingActionButton ? (FloatingActionButton) viewC : null;
        return floatingActionButton != null && floatingActionButton.i();
    }

    public final void G(int i, boolean z) {
        int i2 = 2;
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        if (!isLaidOut()) {
            this.w1 = false;
            return;
        }
        AnimatorSet animatorSet = this.k1;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        ArrayList arrayList = new ArrayList();
        if (!F()) {
            i = 0;
            z = false;
        }
        ActionMenuView actionMenuView = getActionMenuView();
        if (actionMenuView != null) {
            float fabAlignmentAnimationDuration = getFabAlignmentAnimationDuration();
            ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(actionMenuView, "alpha", 1.0f);
            objectAnimatorOfFloat.setDuration((long) (0.8f * fabAlignmentAnimationDuration));
            if (Math.abs(actionMenuView.getTranslationX() - D(actionMenuView, i, z)) > 1.0f) {
                ObjectAnimator objectAnimatorOfFloat2 = ObjectAnimator.ofFloat(actionMenuView, "alpha", DefinitionKt.NO_Float_VALUE);
                objectAnimatorOfFloat2.setDuration((long) (fabAlignmentAnimationDuration * 0.2f));
                objectAnimatorOfFloat2.addListener(new d(this, actionMenuView, i, z));
                AnimatorSet animatorSet2 = new AnimatorSet();
                animatorSet2.playSequentially(objectAnimatorOfFloat2, objectAnimatorOfFloat);
                arrayList.add(animatorSet2);
            } else if (actionMenuView.getAlpha() < 1.0f) {
                arrayList.add(objectAnimatorOfFloat);
            }
        }
        AnimatorSet animatorSet3 = new AnimatorSet();
        animatorSet3.playTogether(arrayList);
        this.k1 = animatorSet3;
        animatorSet3.addListener(new a(this, i2));
        this.k1.start();
    }

    public final void H() {
        ActionMenuView actionMenuView = getActionMenuView();
        if (actionMenuView == null || this.k1 != null) {
            return;
        }
        actionMenuView.setAlpha(1.0f);
        if (F()) {
            K(actionMenuView, this.l1, this.x1, false);
        } else {
            K(actionMenuView, 0, false, false);
        }
    }

    public final void I() {
        getTopEdgeTreatment().f = getFabTranslationX();
        this.i1.n((this.x1 && F() && this.n1 == 1) ? 1.0f : DefinitionKt.NO_Float_VALUE);
        View viewC = C();
        if (viewC != null) {
            viewC.setTranslationY(getFabTranslationY());
            viewC.setTranslationX(getFabTranslationX());
        }
    }

    public final void J(int i) {
        float f = i;
        if (f != getTopEdgeTreatment().d) {
            getTopEdgeTreatment().d = f;
            this.i1.invalidateSelf();
        }
    }

    public final void K(ActionMenuView actionMenuView, int i, boolean z, boolean z2) {
        androidx.work.impl.utils.j jVar = new androidx.work.impl.utils.j(this, actionMenuView, i, z);
        if (z2) {
            actionMenuView.post(jVar);
        } else {
            jVar.run();
        }
    }

    public ColorStateList getBackgroundTint() {
        return this.i1.a.e;
    }

    public float getCradleVerticalOffset() {
        return getTopEdgeTreatment().e;
    }

    public int getFabAlignmentMode() {
        return this.l1;
    }

    public int getFabAlignmentModeEndMargin() {
        return this.p1;
    }

    public int getFabAnchorMode() {
        return this.n1;
    }

    public int getFabAnimationMode() {
        return this.m1;
    }

    public float getFabCradleMargin() {
        return getTopEdgeTreatment().c;
    }

    public float getFabCradleRoundedCornerRadius() {
        return getTopEdgeTreatment().b;
    }

    public boolean getHideOnScroll() {
        return this.s1;
    }

    public int getMenuAlignmentMode() {
        return this.q1;
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        AbstractC3466h4.b(this, this.i1);
        if (getParent() instanceof ViewGroup) {
            ((ViewGroup) getParent()).setClipChildren(false);
        }
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        if (z) {
            AnimatorSet animatorSet = this.k1;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            AnimatorSet animatorSet2 = this.j1;
            if (animatorSet2 != null) {
                animatorSet2.cancel();
            }
            I();
            View viewC = C();
            if (viewC != null) {
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                if (viewC.isLaidOut()) {
                    viewC.post(new RunnableC1068z(viewC, 2));
                }
            }
        }
        H();
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.a);
        this.l1 = savedState.c;
        this.x1 = savedState.d;
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.c = this.l1;
        savedState.d = this.x1;
        return savedState;
    }

    public void setBackgroundTint(ColorStateList colorStateList) {
        this.i1.setTintList(colorStateList);
    }

    public void setCradleVerticalOffset(float f) {
        if (f != getCradleVerticalOffset()) {
            getTopEdgeTreatment().y(f);
            this.i1.invalidateSelf();
            I();
        }
    }

    @Override // android.view.View
    public void setElevation(float f) {
        com.google.android.material.shape.g gVar = this.i1;
        gVar.l(f);
        int iH = gVar.a.o - gVar.h();
        Behavior behavior = getBehavior();
        behavior.h = iH;
        if (behavior.g == 1) {
            setTranslationY(behavior.f + iH);
        }
    }

    public void setFabAlignmentMode(int i) {
        int i2 = 1;
        this.w1 = true;
        G(i, this.x1);
        if (this.l1 != i) {
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            if (isLaidOut()) {
                AnimatorSet animatorSet = this.j1;
                if (animatorSet != null) {
                    animatorSet.cancel();
                }
                ArrayList arrayList = new ArrayList();
                if (this.m1 == 1) {
                    View viewC = C();
                    ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(viewC instanceof FloatingActionButton ? (FloatingActionButton) viewC : null, "translationX", E(i));
                    objectAnimatorOfFloat.setDuration(getFabAlignmentAnimationDuration());
                    arrayList.add(objectAnimatorOfFloat);
                } else {
                    View viewC2 = C();
                    FloatingActionButton floatingActionButton = viewC2 instanceof FloatingActionButton ? (FloatingActionButton) viewC2 : null;
                    if (floatingActionButton != null && !floatingActionButton.h()) {
                        floatingActionButton.g(new c(this, i), true);
                    }
                }
                AnimatorSet animatorSet2 = new AnimatorSet();
                animatorSet2.playTogether(arrayList);
                animatorSet2.setInterpolator(AbstractC3430b4.e(getContext(), R.attr.motionEasingEmphasizedInterpolator, com.google.android.material.animation.a.a));
                this.j1 = animatorSet2;
                animatorSet2.addListener(new a(this, i2));
                this.j1.start();
            }
        }
        this.l1 = i;
    }

    public void setFabAlignmentModeEndMargin(int i) {
        if (this.p1 != i) {
            this.p1 = i;
            I();
        }
    }

    public void setFabAnchorMode(int i) {
        this.n1 = i;
        I();
        View viewC = C();
        if (viewC != null) {
            L(this, viewC);
            viewC.requestLayout();
            this.i1.invalidateSelf();
        }
    }

    public void setFabAnimationMode(int i) {
        this.m1 = i;
    }

    public void setFabCornerSize(float f) {
        if (f != getTopEdgeTreatment().g) {
            getTopEdgeTreatment().g = f;
            this.i1.invalidateSelf();
        }
    }

    public void setFabCradleMargin(float f) {
        if (f != getFabCradleMargin()) {
            getTopEdgeTreatment().c = f;
            this.i1.invalidateSelf();
        }
    }

    public void setFabCradleRoundedCornerRadius(float f) {
        if (f != getFabCradleRoundedCornerRadius()) {
            getTopEdgeTreatment().b = f;
            this.i1.invalidateSelf();
        }
    }

    public void setHideOnScroll(boolean z) {
        this.s1 = z;
    }

    public void setMenuAlignmentMode(int i) {
        if (this.q1 != i) {
            this.q1 = i;
            ActionMenuView actionMenuView = getActionMenuView();
            if (actionMenuView != null) {
                K(actionMenuView, this.l1, F(), false);
            }
        }
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setNavigationIcon(Drawable drawable) {
        if (drawable != null && this.h1 != null) {
            drawable = drawable.mutate();
            drawable.setTint(this.h1.intValue());
        }
        super.setNavigationIcon(drawable);
    }

    public void setNavigationIconTint(int i) {
        this.h1 = Integer.valueOf(i);
        Drawable navigationIcon = getNavigationIcon();
        if (navigationIcon != null) {
            setNavigationIcon(navigationIcon);
        }
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setSubtitle(CharSequence charSequence) {
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setTitle(CharSequence charSequence) {
    }

    @Override // androidx.coordinatorlayout.widget.a
    @NonNull
    public Behavior getBehavior() {
        if (this.y1 == null) {
            this.y1 = new Behavior();
        }
        return this.y1;
    }

    public static class Behavior extends HideBottomViewOnScrollBehavior<BottomAppBar> {
        public final Rect j;
        public WeakReference k;
        public int l;
        public final e m;

        public Behavior() {
            this.m = new e(this);
            this.j = new Rect();
        }

        @Override // com.google.android.material.behavior.HideBottomViewOnScrollBehavior, androidx.coordinatorlayout.widget.b
        public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
            BottomAppBar bottomAppBar = (BottomAppBar) view;
            this.k = new WeakReference(bottomAppBar);
            int i2 = BottomAppBar.E1;
            View viewC = bottomAppBar.C();
            if (viewC != null) {
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                if (!viewC.isLaidOut()) {
                    BottomAppBar.L(bottomAppBar, viewC);
                    this.l = ((ViewGroup.MarginLayoutParams) ((androidx.coordinatorlayout.widget.e) viewC.getLayoutParams())).bottomMargin;
                    if (viewC instanceof FloatingActionButton) {
                        FloatingActionButton floatingActionButton = (FloatingActionButton) viewC;
                        if (bottomAppBar.n1 == 0 && bottomAppBar.r1) {
                            androidx.core.view.L.k(floatingActionButton, DefinitionKt.NO_Float_VALUE);
                            floatingActionButton.setCompatElevation(DefinitionKt.NO_Float_VALUE);
                        }
                        if (floatingActionButton.getShowMotionSpec() == null) {
                            floatingActionButton.setShowMotionSpecResource(R.animator.mtrl_fab_show_motion_spec);
                        }
                        if (floatingActionButton.getHideMotionSpec() == null) {
                            floatingActionButton.setHideMotionSpecResource(R.animator.mtrl_fab_hide_motion_spec);
                        }
                        floatingActionButton.c(bottomAppBar.C1);
                        floatingActionButton.d(new a(bottomAppBar, 3));
                        floatingActionButton.e(bottomAppBar.D1);
                    }
                    viewC.addOnLayoutChangeListener(this.m);
                    bottomAppBar.I();
                }
            }
            coordinatorLayout.r(i, bottomAppBar);
            super.l(coordinatorLayout, bottomAppBar, i);
            return false;
        }

        @Override // com.google.android.material.behavior.HideBottomViewOnScrollBehavior, androidx.coordinatorlayout.widget.b
        public final boolean t(CoordinatorLayout coordinatorLayout, View view, View view2, View view3, int i, int i2) {
            BottomAppBar bottomAppBar = (BottomAppBar) view;
            return bottomAppBar.getHideOnScroll() && super.t(coordinatorLayout, bottomAppBar, view2, view3, i, i2);
        }

        public Behavior(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.m = new e(this);
            this.j = new Rect();
        }
    }
}
