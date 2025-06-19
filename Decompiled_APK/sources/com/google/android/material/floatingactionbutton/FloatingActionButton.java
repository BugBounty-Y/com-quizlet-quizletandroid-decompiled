package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Matrix;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.C0070a;
import androidx.appcompat.widget.C0112u;
import androidx.appcompat.widget.C0122z;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.Z3;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.internal.t;
import com.google.android.material.stateful.ExtendableSavedState;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class FloatingActionButton extends t implements com.google.android.material.expandable.a, com.google.android.material.shape.s, androidx.coordinatorlayout.widget.a {
    public ColorStateList b;
    public PorterDuff.Mode c;
    public ColorStateList d;
    public PorterDuff.Mode e;
    public ColorStateList f;
    public int g;
    public int h;
    public int i;
    public int j;
    public boolean k;
    public final Rect l;
    public final Rect m;
    public final C0122z n;
    public final C0070a o;
    public s p;

    public static class Behavior extends BaseBehavior<FloatingActionButton> {
        public Behavior() {
        }

        public Behavior(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
        }
    }

    public FloatingActionButton(@NonNull Context context) {
        this(context, null);
    }

    private q getImpl() {
        if (this.p == null) {
            this.p = new s(this, new com.google.firebase.platforminfo.c(this));
        }
        return this.p;
    }

    public final void c(AnimatorListenerAdapter animatorListenerAdapter) {
        q impl = getImpl();
        if (impl.t == null) {
            impl.t = new ArrayList();
        }
        impl.t.add(animatorListenerAdapter);
    }

    public final void d(com.google.android.material.bottomappbar.a aVar) {
        q impl = getImpl();
        if (impl.s == null) {
            impl.s = new ArrayList();
        }
        impl.s.add(aVar);
    }

    @Override // android.widget.ImageView, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        getImpl().j(getDrawableState());
    }

    public final void e(com.google.firebase.platforminfo.c cVar) {
        q impl = getImpl();
        h hVar = new h(this, cVar);
        if (impl.u == null) {
            impl.u = new ArrayList();
        }
        impl.u.add(hVar);
    }

    public final int f(int i) {
        int i2 = this.h;
        if (i2 != 0) {
            return i2;
        }
        Resources resources = getResources();
        return i != -1 ? i != 1 ? resources.getDimensionPixelSize(R.dimen.design_fab_size_normal) : resources.getDimensionPixelSize(R.dimen.design_fab_size_mini) : Math.max(resources.getConfiguration().screenWidthDp, resources.getConfiguration().screenHeightDp) < 470 ? f(1) : f(0);
    }

    public final void g(com.google.android.material.bottomappbar.c cVar, boolean z) {
        q impl = getImpl();
        com.quizlet.data.repository.qclass.c cVar2 = cVar == null ? null : new com.quizlet.data.repository.qclass.c((Object) this, false, (Object) cVar, 11);
        if (impl.v.getVisibility() == 0) {
            if (impl.r == 1) {
                return;
            }
        } else if (impl.r != 2) {
            return;
        }
        Animator animator = impl.l;
        if (animator != null) {
            animator.cancel();
        }
        WeakHashMap weakHashMap = V.a;
        FloatingActionButton floatingActionButton = impl.v;
        if (!floatingActionButton.isLaidOut() || floatingActionButton.isInEditMode()) {
            floatingActionButton.a(z ? 8 : 4, z);
            if (cVar2 != null) {
                ((Z3) cVar2.b).a((FloatingActionButton) cVar2.c);
                return;
            }
            return;
        }
        com.google.android.material.animation.f fVar = impl.n;
        AnimatorSet animatorSetB = fVar != null ? impl.b(fVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) : impl.c(DefinitionKt.NO_Float_VALUE, 0.4f, 0.4f, q.F, q.G);
        animatorSetB.addListener(new i(impl, z, cVar2));
        ArrayList arrayList = impl.t;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                animatorSetB.addListener((Animator.AnimatorListener) it2.next());
            }
        }
        animatorSetB.start();
    }

    @Override // android.view.View
    public ColorStateList getBackgroundTintList() {
        return this.b;
    }

    @Override // android.view.View
    public PorterDuff.Mode getBackgroundTintMode() {
        return this.c;
    }

    @Override // androidx.coordinatorlayout.widget.a
    @NonNull
    public androidx.coordinatorlayout.widget.b getBehavior() {
        return new Behavior();
    }

    public float getCompatElevation() {
        return getImpl().e();
    }

    public float getCompatHoveredFocusedTranslationZ() {
        return getImpl().i;
    }

    public float getCompatPressedTranslationZ() {
        return getImpl().j;
    }

    public Drawable getContentBackground() {
        return getImpl().e;
    }

    public int getCustomSize() {
        return this.h;
    }

    public int getExpandedComponentIdHint() {
        return this.o.a;
    }

    public com.google.android.material.animation.f getHideMotionSpec() {
        return getImpl().n;
    }

    @Deprecated
    public int getRippleColor() {
        ColorStateList colorStateList = this.f;
        if (colorStateList != null) {
            return colorStateList.getDefaultColor();
        }
        return 0;
    }

    public ColorStateList getRippleColorStateList() {
        return this.f;
    }

    @NonNull
    public com.google.android.material.shape.j getShapeAppearanceModel() {
        com.google.android.material.shape.j jVar = getImpl().a;
        jVar.getClass();
        return jVar;
    }

    public com.google.android.material.animation.f getShowMotionSpec() {
        return getImpl().m;
    }

    public int getSize() {
        return this.g;
    }

    public int getSizeDimension() {
        return f(this.g);
    }

    public ColorStateList getSupportBackgroundTintList() {
        return getBackgroundTintList();
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        return getBackgroundTintMode();
    }

    public ColorStateList getSupportImageTintList() {
        return this.d;
    }

    public PorterDuff.Mode getSupportImageTintMode() {
        return this.e;
    }

    public boolean getUseCompatPadding() {
        return this.k;
    }

    public final boolean h() {
        q impl = getImpl();
        if (impl.v.getVisibility() == 0) {
            if (impl.r != 1) {
                return false;
            }
        } else if (impl.r == 2) {
            return false;
        }
        return true;
    }

    public final boolean i() {
        q impl = getImpl();
        if (impl.v.getVisibility() != 0) {
            if (impl.r != 2) {
                return false;
            }
        } else if (impl.r == 1) {
            return false;
        }
        return true;
    }

    public final void j(Rect rect) {
        int i = rect.left;
        Rect rect2 = this.l;
        rect.left = i + rect2.left;
        rect.top += rect2.top;
        rect.right -= rect2.right;
        rect.bottom -= rect2.bottom;
    }

    @Override // android.widget.ImageView, android.view.View
    public final void jumpDrawablesToCurrentState() {
        super.jumpDrawablesToCurrentState();
        getImpl().h();
    }

    public final void k() {
        Drawable drawable = getDrawable();
        if (drawable == null) {
            return;
        }
        ColorStateList colorStateList = this.d;
        if (colorStateList == null) {
            drawable.clearColorFilter();
            return;
        }
        int colorForState = colorStateList.getColorForState(getDrawableState(), 0);
        PorterDuff.Mode mode = this.e;
        if (mode == null) {
            mode = PorterDuff.Mode.SRC_IN;
        }
        drawable.mutate().setColorFilter(C0112u.c(colorForState, mode));
    }

    public final void l(com.google.android.material.bottomappbar.b bVar, boolean z) {
        boolean z2 = false;
        q impl = getImpl();
        com.quizlet.data.repository.qclass.c cVar = bVar == null ? null : new com.quizlet.data.repository.qclass.c(this, z2, bVar, 11);
        if (impl.v.getVisibility() != 0) {
            if (impl.r == 2) {
                return;
            }
        } else if (impl.r != 1) {
            return;
        }
        Animator animator = impl.l;
        if (animator != null) {
            animator.cancel();
        }
        boolean z3 = impl.m == null;
        WeakHashMap weakHashMap = V.a;
        FloatingActionButton floatingActionButton = impl.v;
        boolean z4 = floatingActionButton.isLaidOut() && !floatingActionButton.isInEditMode();
        Matrix matrix = impl.A;
        if (!z4) {
            floatingActionButton.a(0, z);
            floatingActionButton.setAlpha(1.0f);
            floatingActionButton.setScaleY(1.0f);
            floatingActionButton.setScaleX(1.0f);
            impl.p = 1.0f;
            impl.a(1.0f, matrix);
            floatingActionButton.setImageMatrix(matrix);
            if (cVar != null) {
                ((Z3) cVar.b).b();
                return;
            }
            return;
        }
        if (floatingActionButton.getVisibility() != 0) {
            float f = DefinitionKt.NO_Float_VALUE;
            floatingActionButton.setAlpha(DefinitionKt.NO_Float_VALUE);
            floatingActionButton.setScaleY(z3 ? 0.4f : 0.0f);
            floatingActionButton.setScaleX(z3 ? 0.4f : 0.0f);
            if (z3) {
                f = 0.4f;
            }
            impl.p = f;
            impl.a(f, matrix);
            floatingActionButton.setImageMatrix(matrix);
        }
        com.google.android.material.animation.f fVar = impl.m;
        AnimatorSet animatorSetB = fVar != null ? impl.b(fVar, 1.0f, 1.0f, 1.0f) : impl.c(1.0f, 1.0f, 1.0f, q.D, q.E);
        animatorSetB.addListener(new j(impl, z, cVar));
        ArrayList arrayList = impl.s;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                animatorSetB.addListener((Animator.AnimatorListener) it2.next());
            }
        }
        animatorSetB.start();
    }

    @Override // android.widget.ImageView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        q impl = getImpl();
        com.google.android.material.shape.g gVar = impl.b;
        FloatingActionButton floatingActionButton = impl.v;
        if (gVar != null) {
            AbstractC3466h4.b(floatingActionButton, gVar);
        }
        if (impl instanceof s) {
            return;
        }
        ViewTreeObserver viewTreeObserver = floatingActionButton.getViewTreeObserver();
        if (impl.B == null) {
            impl.B = new androidx.coordinatorlayout.widget.f(impl, 2);
        }
        viewTreeObserver.addOnPreDrawListener(impl.B);
    }

    @Override // android.widget.ImageView, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        q impl = getImpl();
        ViewTreeObserver viewTreeObserver = impl.v.getViewTreeObserver();
        androidx.coordinatorlayout.widget.f fVar = impl.B;
        if (fVar != null) {
            viewTreeObserver.removeOnPreDrawListener(fVar);
            impl.B = null;
        }
    }

    @Override // android.widget.ImageView, android.view.View
    public final void onMeasure(int i, int i2) {
        int sizeDimension = getSizeDimension();
        this.i = (sizeDimension - this.j) / 2;
        getImpl().r();
        int iMin = Math.min(View.resolveSize(sizeDimension, i), View.resolveSize(sizeDimension, i2));
        Rect rect = this.l;
        setMeasuredDimension(rect.left + iMin + rect.right, iMin + rect.top + rect.bottom);
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof ExtendableSavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        ExtendableSavedState extendableSavedState = (ExtendableSavedState) parcelable;
        super.onRestoreInstanceState(extendableSavedState.a);
        Bundle bundle = (Bundle) extendableSavedState.c.get("expandableWidgetHelper");
        bundle.getClass();
        C0070a c0070a = this.o;
        c0070a.getClass();
        c0070a.b = bundle.getBoolean("expanded", false);
        c0070a.a = bundle.getInt("expandedComponentIdHint", 0);
        if (c0070a.b) {
            View view = (View) c0070a.c;
            ViewParent parent = view.getParent();
            if (parent instanceof CoordinatorLayout) {
                ((CoordinatorLayout) parent).d(view);
            }
        }
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        Parcelable parcelableOnSaveInstanceState = super.onSaveInstanceState();
        if (parcelableOnSaveInstanceState == null) {
            parcelableOnSaveInstanceState = new Bundle();
        }
        ExtendableSavedState extendableSavedState = new ExtendableSavedState(parcelableOnSaveInstanceState);
        androidx.collection.V v = extendableSavedState.c;
        C0070a c0070a = this.o;
        c0070a.getClass();
        Bundle bundle = new Bundle();
        bundle.putBoolean("expanded", c0070a.b);
        bundle.putInt("expandedComponentIdHint", c0070a.a);
        v.put("expandableWidgetHelper", bundle);
        return extendableSavedState;
    }

    @Override // android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        if (motionEvent.getAction() == 0) {
            int measuredWidth = getMeasuredWidth();
            int measuredHeight = getMeasuredHeight();
            Rect rect = this.m;
            rect.set(0, 0, measuredWidth, measuredHeight);
            j(rect);
            s sVar = this.p;
            int i = -(sVar.f ? Math.max((sVar.k - sVar.v.getSizeDimension()) / 2, 0) : 0);
            rect.inset(i, i);
            if (!rect.contains((int) motionEvent.getX(), (int) motionEvent.getY())) {
                return false;
            }
        }
        return super.onTouchEvent(motionEvent);
    }

    @Override // android.view.View
    public void setBackgroundColor(int i) {
        Log.i("FloatingActionButton", "Setting a custom background is not supported.");
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        Log.i("FloatingActionButton", "Setting a custom background is not supported.");
    }

    @Override // android.view.View
    public void setBackgroundResource(int i) {
        Log.i("FloatingActionButton", "Setting a custom background is not supported.");
    }

    @Override // android.view.View
    public void setBackgroundTintList(ColorStateList colorStateList) {
        if (this.b != colorStateList) {
            this.b = colorStateList;
            q impl = getImpl();
            com.google.android.material.shape.g gVar = impl.b;
            if (gVar != null) {
                gVar.setTintList(colorStateList);
            }
            b bVar = impl.d;
            if (bVar != null) {
                if (colorStateList != null) {
                    bVar.m = colorStateList.getColorForState(bVar.getState(), bVar.m);
                }
                bVar.p = colorStateList;
                bVar.n = true;
                bVar.invalidateSelf();
            }
        }
    }

    @Override // android.view.View
    public void setBackgroundTintMode(PorterDuff.Mode mode) {
        if (this.c != mode) {
            this.c = mode;
            com.google.android.material.shape.g gVar = getImpl().b;
            if (gVar != null) {
                gVar.setTintMode(mode);
            }
        }
    }

    public void setCompatElevation(float f) {
        q impl = getImpl();
        if (impl.h != f) {
            impl.h = f;
            impl.k(f, impl.i, impl.j);
        }
    }

    public void setCompatElevationResource(int i) {
        setCompatElevation(getResources().getDimension(i));
    }

    public void setCompatHoveredFocusedTranslationZ(float f) {
        q impl = getImpl();
        if (impl.i != f) {
            impl.i = f;
            impl.k(impl.h, f, impl.j);
        }
    }

    public void setCompatHoveredFocusedTranslationZResource(int i) {
        setCompatHoveredFocusedTranslationZ(getResources().getDimension(i));
    }

    public void setCompatPressedTranslationZ(float f) {
        q impl = getImpl();
        if (impl.j != f) {
            impl.j = f;
            impl.k(impl.h, impl.i, f);
        }
    }

    public void setCompatPressedTranslationZResource(int i) {
        setCompatPressedTranslationZ(getResources().getDimension(i));
    }

    public void setCustomSize(int i) {
        if (i < 0) {
            throw new IllegalArgumentException("Custom size must be non-negative");
        }
        if (i != this.h) {
            this.h = i;
            requestLayout();
        }
    }

    @Override // android.view.View
    public void setElevation(float f) {
        super.setElevation(f);
        com.google.android.material.shape.g gVar = getImpl().b;
        if (gVar != null) {
            gVar.l(f);
        }
    }

    public void setEnsureMinTouchTargetSize(boolean z) {
        if (z != getImpl().f) {
            getImpl().f = z;
            requestLayout();
        }
    }

    public void setExpandedComponentIdHint(int i) {
        this.o.a = i;
    }

    public void setHideMotionSpec(com.google.android.material.animation.f fVar) {
        getImpl().n = fVar;
    }

    public void setHideMotionSpecResource(int i) {
        setHideMotionSpec(com.google.android.material.animation.f.b(getContext(), i));
    }

    @Override // android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        if (getDrawable() != drawable) {
            super.setImageDrawable(drawable);
            q impl = getImpl();
            float f = impl.p;
            impl.p = f;
            Matrix matrix = impl.A;
            impl.a(f, matrix);
            impl.v.setImageMatrix(matrix);
            if (this.d != null) {
                k();
            }
        }
    }

    @Override // android.widget.ImageView
    public void setImageResource(int i) {
        this.n.x(i);
        k();
    }

    public void setMaxImageSize(int i) {
        this.j = i;
        q impl = getImpl();
        if (impl.q != i) {
            impl.q = i;
            float f = impl.p;
            impl.p = f;
            Matrix matrix = impl.A;
            impl.a(f, matrix);
            impl.v.setImageMatrix(matrix);
        }
    }

    public void setRippleColor(int i) {
        setRippleColor(ColorStateList.valueOf(i));
    }

    @Override // android.view.View
    public void setScaleX(float f) {
        super.setScaleX(f);
        getImpl().l();
    }

    @Override // android.view.View
    public void setScaleY(float f) {
        super.setScaleY(f);
        getImpl().l();
    }

    public void setShadowPaddingEnabled(boolean z) {
        q impl = getImpl();
        impl.g = z;
        impl.r();
    }

    @Override // com.google.android.material.shape.s
    public void setShapeAppearanceModel(@NonNull com.google.android.material.shape.j jVar) {
        getImpl().o(jVar);
    }

    public void setShowMotionSpec(com.google.android.material.animation.f fVar) {
        getImpl().m = fVar;
    }

    public void setShowMotionSpecResource(int i) {
        setShowMotionSpec(com.google.android.material.animation.f.b(getContext(), i));
    }

    public void setSize(int i) {
        this.h = 0;
        if (i != this.g) {
            this.g = i;
            requestLayout();
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        setBackgroundTintList(colorStateList);
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        setBackgroundTintMode(mode);
    }

    public void setSupportImageTintList(ColorStateList colorStateList) {
        if (this.d != colorStateList) {
            this.d = colorStateList;
            k();
        }
    }

    public void setSupportImageTintMode(PorterDuff.Mode mode) {
        if (this.e != mode) {
            this.e = mode;
            k();
        }
    }

    @Override // android.view.View
    public void setTranslationX(float f) {
        super.setTranslationX(f);
        getImpl().m();
    }

    @Override // android.view.View
    public void setTranslationY(float f) {
        super.setTranslationY(f);
        getImpl().m();
    }

    @Override // android.view.View
    public void setTranslationZ(float f) {
        super.setTranslationZ(f);
        getImpl().m();
    }

    public void setUseCompatPadding(boolean z) {
        if (this.k != z) {
            this.k = z;
            getImpl().i();
        }
    }

    @Override // com.google.android.material.internal.t, android.widget.ImageView, android.view.View
    public void setVisibility(int i) {
        super.setVisibility(i);
    }

    public static class BaseBehavior<T extends FloatingActionButton> extends androidx.coordinatorlayout.widget.b {
        public Rect a;
        public final boolean b;

        public BaseBehavior() {
            this.b = true;
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final boolean e(Rect rect, View view) {
            FloatingActionButton floatingActionButton = (FloatingActionButton) view;
            int left = floatingActionButton.getLeft();
            Rect rect2 = floatingActionButton.l;
            rect.set(left + rect2.left, floatingActionButton.getTop() + rect2.top, floatingActionButton.getRight() - rect2.right, floatingActionButton.getBottom() - rect2.bottom);
            return true;
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final void g(androidx.coordinatorlayout.widget.e eVar) {
            if (eVar.h == 0) {
                eVar.h = 80;
            }
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final boolean h(CoordinatorLayout coordinatorLayout, View view, View view2) {
            FloatingActionButton floatingActionButton = (FloatingActionButton) view;
            if (view2 instanceof AppBarLayout) {
                w(coordinatorLayout, (AppBarLayout) view2, floatingActionButton);
            } else {
                ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
                if (layoutParams instanceof androidx.coordinatorlayout.widget.e ? ((androidx.coordinatorlayout.widget.e) layoutParams).a instanceof BottomSheetBehavior : false) {
                    x(view2, floatingActionButton);
                }
            }
            return false;
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
            FloatingActionButton floatingActionButton = (FloatingActionButton) view;
            ArrayList arrayListK = coordinatorLayout.k(floatingActionButton);
            int size = arrayListK.size();
            int i2 = 0;
            for (int i3 = 0; i3 < size; i3++) {
                View view2 = (View) arrayListK.get(i3);
                if (!(view2 instanceof AppBarLayout)) {
                    ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
                    if ((layoutParams instanceof androidx.coordinatorlayout.widget.e ? ((androidx.coordinatorlayout.widget.e) layoutParams).a instanceof BottomSheetBehavior : false) && x(view2, floatingActionButton)) {
                        break;
                    }
                } else {
                    if (w(coordinatorLayout, (AppBarLayout) view2, floatingActionButton)) {
                        break;
                    }
                }
            }
            coordinatorLayout.r(i, floatingActionButton);
            Rect rect = floatingActionButton.l;
            if (rect != null && rect.centerX() > 0 && rect.centerY() > 0) {
                androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) floatingActionButton.getLayoutParams();
                int i4 = floatingActionButton.getRight() >= coordinatorLayout.getWidth() - ((ViewGroup.MarginLayoutParams) eVar).rightMargin ? rect.right : floatingActionButton.getLeft() <= ((ViewGroup.MarginLayoutParams) eVar).leftMargin ? -rect.left : 0;
                if (floatingActionButton.getBottom() >= coordinatorLayout.getHeight() - ((ViewGroup.MarginLayoutParams) eVar).bottomMargin) {
                    i2 = rect.bottom;
                } else if (floatingActionButton.getTop() <= ((ViewGroup.MarginLayoutParams) eVar).topMargin) {
                    i2 = -rect.top;
                }
                if (i2 != 0) {
                    WeakHashMap weakHashMap = V.a;
                    floatingActionButton.offsetTopAndBottom(i2);
                }
                if (i4 != 0) {
                    WeakHashMap weakHashMap2 = V.a;
                    floatingActionButton.offsetLeftAndRight(i4);
                }
            }
            return true;
        }

        public final boolean w(CoordinatorLayout coordinatorLayout, AppBarLayout appBarLayout, FloatingActionButton floatingActionButton) {
            if (!(this.b && ((androidx.coordinatorlayout.widget.e) floatingActionButton.getLayoutParams()).f == appBarLayout.getId() && floatingActionButton.getUserSetVisibility() == 0)) {
                return false;
            }
            if (this.a == null) {
                this.a = new Rect();
            }
            Rect rect = this.a;
            com.google.android.material.internal.c.a(coordinatorLayout, appBarLayout, rect);
            if (rect.bottom <= appBarLayout.getMinimumHeightForVisibleOverlappingContent()) {
                floatingActionButton.g(null, false);
            } else {
                floatingActionButton.l(null, false);
            }
            return true;
        }

        public final boolean x(View view, FloatingActionButton floatingActionButton) {
            if (!(this.b && ((androidx.coordinatorlayout.widget.e) floatingActionButton.getLayoutParams()).f == view.getId() && floatingActionButton.getUserSetVisibility() == 0)) {
                return false;
            }
            if (view.getTop() < (floatingActionButton.getHeight() / 2) + ((ViewGroup.MarginLayoutParams) ((androidx.coordinatorlayout.widget.e) floatingActionButton.getLayoutParams())).topMargin) {
                floatingActionButton.g(null, false);
            } else {
                floatingActionButton.l(null, false);
            }
            return true;
        }

        public BaseBehavior(Context context, AttributeSet attributeSet) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.q);
            this.b = typedArrayObtainStyledAttributes.getBoolean(0, true);
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    public FloatingActionButton(@NonNull Context context, AttributeSet attributeSet) throws Resources.NotFoundException {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, R.attr.floatingActionButtonStyle, R.style.Widget_Design_FloatingActionButton), attributeSet, R.attr.floatingActionButtonStyle);
        this.l = new Rect();
        this.m = new Rect();
        Context context2 = getContext();
        TypedArray typedArrayL = com.google.android.material.internal.p.l(context2, attributeSet, com.google.android.material.a.p, R.attr.floatingActionButtonStyle, R.style.Widget_Design_FloatingActionButton, new int[0]);
        this.b = AbstractC3442d4.a(context2, typedArrayL, 1);
        this.c = com.google.android.material.internal.p.m(typedArrayL.getInt(2, -1), null);
        this.f = AbstractC3442d4.a(context2, typedArrayL, 12);
        this.g = typedArrayL.getInt(7, -1);
        this.h = typedArrayL.getDimensionPixelSize(6, 0);
        int dimensionPixelSize = typedArrayL.getDimensionPixelSize(3, 0);
        float dimension = typedArrayL.getDimension(4, DefinitionKt.NO_Float_VALUE);
        float dimension2 = typedArrayL.getDimension(9, DefinitionKt.NO_Float_VALUE);
        float dimension3 = typedArrayL.getDimension(11, DefinitionKt.NO_Float_VALUE);
        this.k = typedArrayL.getBoolean(16, false);
        int dimensionPixelSize2 = getResources().getDimensionPixelSize(R.dimen.mtrl_fab_min_touch_target);
        setMaxImageSize(typedArrayL.getDimensionPixelSize(10, 0));
        com.google.android.material.animation.f fVarA = com.google.android.material.animation.f.a(context2, typedArrayL, 15);
        com.google.android.material.animation.f fVarA2 = com.google.android.material.animation.f.a(context2, typedArrayL, 8);
        com.google.android.material.shape.j jVarA = com.google.android.material.shape.j.c(context2, attributeSet, R.attr.floatingActionButtonStyle, R.style.Widget_Design_FloatingActionButton, com.google.android.material.shape.j.m).a();
        boolean z = typedArrayL.getBoolean(5, false);
        setEnabled(typedArrayL.getBoolean(0, true));
        typedArrayL.recycle();
        C0122z c0122z = new C0122z(this);
        this.n = c0122z;
        c0122z.t(attributeSet, R.attr.floatingActionButtonStyle);
        C0070a c0070a = new C0070a();
        c0070a.b = false;
        c0070a.a = 0;
        c0070a.c = this;
        this.o = c0070a;
        getImpl().o(jVarA);
        getImpl().g(this.b, this.c, this.f, dimensionPixelSize);
        getImpl().k = dimensionPixelSize2;
        q impl = getImpl();
        if (impl.h != dimension) {
            impl.h = dimension;
            impl.k(dimension, impl.i, impl.j);
        }
        q impl2 = getImpl();
        if (impl2.i != dimension2) {
            impl2.i = dimension2;
            impl2.k(impl2.h, dimension2, impl2.j);
        }
        q impl3 = getImpl();
        if (impl3.j != dimension3) {
            impl3.j = dimension3;
            impl3.k(impl3.h, impl3.i, dimension3);
        }
        getImpl().m = fVarA;
        getImpl().n = fVarA2;
        getImpl().f = z;
        setScaleType(ImageView.ScaleType.MATRIX);
    }

    public void setRippleColor(ColorStateList colorStateList) {
        if (this.f != colorStateList) {
            this.f = colorStateList;
            getImpl().n(this.f);
        }
    }
}
