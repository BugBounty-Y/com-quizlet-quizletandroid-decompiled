package com.google.android.material.floatingactionbutton;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.k1;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.V;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.button.MaterialButton;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class ExtendedFloatingActionButton extends MaterialButton implements androidx.coordinatorlayout.widget.a {
    public static final k1 I = new k1(8, Float.class, OTUXParamsKeys.OT_UX_WIDTH);
    public static final k1 J = new k1(9, Float.class, OTUXParamsKeys.OT_UX_HEIGHT);
    public static final k1 K = new k1(10, Float.class, "paddingStart");
    public static final k1 L = new k1(11, Float.class, "paddingEnd");
    public int A;
    public final ExtendedFloatingActionButtonBehavior B;
    public boolean C;
    public boolean D;
    public boolean E;
    public ColorStateList F;
    public int G;
    public int H;
    public int t;
    public final d u;
    public final d v;
    public final f w;
    public final e x;
    public final int y;
    public int z;

    public ExtendedFloatingActionButton(@NonNull Context context) {
        boolean z;
        super(com.google.android.material.theme.overlay.a.a(context, null, R.attr.extendedFloatingActionButtonStyle, R.style.Widget_MaterialComponents_ExtendedFloatingActionButton_Icon), null, R.attr.extendedFloatingActionButtonStyle);
        this.t = 0;
        com.airbnb.lottie.network.d dVar = new com.airbnb.lottie.network.d(27, false);
        f fVar = new f(this, dVar);
        this.w = fVar;
        e eVar = new e(this, dVar);
        this.x = eVar;
        this.C = true;
        this.D = false;
        this.E = false;
        Context context2 = getContext();
        this.B = new ExtendedFloatingActionButtonBehavior(context2, null);
        TypedArray typedArrayL = com.google.android.material.internal.p.l(context2, null, com.google.android.material.a.n, R.attr.extendedFloatingActionButtonStyle, R.style.Widget_MaterialComponents_ExtendedFloatingActionButton_Icon, new int[0]);
        com.google.android.material.animation.f fVarA = com.google.android.material.animation.f.a(context2, typedArrayL, 5);
        com.google.android.material.animation.f fVarA2 = com.google.android.material.animation.f.a(context2, typedArrayL, 4);
        com.google.android.material.animation.f fVarA3 = com.google.android.material.animation.f.a(context2, typedArrayL, 2);
        com.google.android.material.animation.f fVarA4 = com.google.android.material.animation.f.a(context2, typedArrayL, 6);
        this.y = typedArrayL.getDimensionPixelSize(0, -1);
        int i = typedArrayL.getInt(3, 1);
        this.z = getPaddingStart();
        this.A = getPaddingEnd();
        com.airbnb.lottie.network.d dVar2 = new com.airbnb.lottie.network.d(27, false);
        g cVar = new c(this, 0);
        g aVar = new com.quizlet.data.repository.explanations.myexplanations.a(11, this, cVar);
        g cVar2 = new com.quizlet.data.repository.course.membership.c(this, aVar, cVar);
        if (i != 1) {
            cVar = i != 2 ? cVar2 : aVar;
            z = true;
        } else {
            z = true;
        }
        d dVar3 = new d(this, dVar2, cVar, z);
        this.v = dVar3;
        d dVar4 = new d(this, dVar2, new com.google.android.gms.auth.api.signin.internal.h(this, 28), false);
        this.u = dVar4;
        fVar.f = fVarA;
        eVar.f = fVarA2;
        dVar3.f = fVarA3;
        dVar4.f = fVarA4;
        typedArrayL.recycle();
        setShapeAppearanceModel(com.google.android.material.shape.j.c(context2, null, R.attr.extendedFloatingActionButtonStyle, R.style.Widget_MaterialComponents_ExtendedFloatingActionButton_Icon, com.google.android.material.shape.j.m).a());
        this.F = getTextColors();
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0045  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void e(com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton r4, int r5) {
        /*
            r0 = 1
            r1 = 2
            if (r5 == 0) goto L20
            if (r5 == r0) goto L1d
            if (r5 == r1) goto L1a
            r2 = 3
            if (r5 != r2) goto Le
            com.google.android.material.floatingactionbutton.d r2 = r4.v
            goto L22
        Le:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r0 = "Unknown strategy type: "
            java.lang.String r5 = android.support.v4.media.session.a.f(r5, r0)
            r4.<init>(r5)
            throw r4
        L1a:
            com.google.android.material.floatingactionbutton.d r2 = r4.u
            goto L22
        L1d:
            com.google.android.material.floatingactionbutton.e r2 = r4.x
            goto L22
        L20:
            com.google.android.material.floatingactionbutton.f r2 = r4.w
        L22:
            boolean r3 = r2.h()
            if (r3 == 0) goto L29
            return
        L29:
            java.util.WeakHashMap r3 = androidx.core.view.V.a
            boolean r3 = r4.isLaidOut()
            if (r3 != 0) goto L45
            int r3 = r4.getVisibility()
            if (r3 == 0) goto L3c
            int r0 = r4.t
            if (r0 != r1) goto L41
            goto L93
        L3c:
            int r3 = r4.t
            if (r3 == r0) goto L41
            goto L93
        L41:
            boolean r0 = r4.E
            if (r0 == 0) goto L93
        L45:
            boolean r0 = r4.isInEditMode()
            if (r0 != 0) goto L93
            if (r5 != r1) goto L68
            android.view.ViewGroup$LayoutParams r5 = r4.getLayoutParams()
            if (r5 == 0) goto L5c
            int r0 = r5.width
            r4.G = r0
            int r5 = r5.height
            r4.H = r5
            goto L68
        L5c:
            int r5 = r4.getWidth()
            r4.G = r5
            int r5 = r4.getHeight()
            r4.H = r5
        L68:
            r5 = 0
            r4.measure(r5, r5)
            android.animation.AnimatorSet r4 = r2.a()
            androidx.appcompat.widget.c r5 = new androidx.appcompat.widget.c
            r0 = 6
            r5.<init>(r2, r0)
            r4.addListener(r5)
            java.util.ArrayList r5 = r2.c
            java.util.Iterator r5 = r5.iterator()
        L7f:
            boolean r0 = r5.hasNext()
            if (r0 == 0) goto L8f
            java.lang.Object r0 = r5.next()
            android.animation.Animator$AnimatorListener r0 = (android.animation.Animator.AnimatorListener) r0
            r4.addListener(r0)
            goto L7f
        L8f:
            r4.start()
            return
        L93:
            r2.g()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton.e(com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton, int):void");
    }

    public final void f(ColorStateList colorStateList) {
        super.setTextColor(colorStateList);
    }

    @Override // androidx.coordinatorlayout.widget.a
    @NonNull
    public androidx.coordinatorlayout.widget.b getBehavior() {
        return this.B;
    }

    public int getCollapsedPadding() {
        return (getCollapsedSize() - getIconSize()) / 2;
    }

    public int getCollapsedSize() {
        int i = this.y;
        if (i >= 0) {
            return i;
        }
        WeakHashMap weakHashMap = V.a;
        return getIconSize() + (Math.min(getPaddingStart(), getPaddingEnd()) * 2);
    }

    public com.google.android.material.animation.f getExtendMotionSpec() {
        return this.v.f;
    }

    public com.google.android.material.animation.f getHideMotionSpec() {
        return this.x.f;
    }

    public com.google.android.material.animation.f getShowMotionSpec() {
        return this.w.f;
    }

    public com.google.android.material.animation.f getShrinkMotionSpec() {
        return this.u.f;
    }

    @Override // com.google.android.material.button.MaterialButton, android.widget.TextView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.C && TextUtils.isEmpty(getText()) && getIcon() != null) {
            this.C = false;
            this.u.g();
        }
    }

    public void setAnimateShowBeforeLayout(boolean z) {
        this.E = z;
    }

    public void setExtendMotionSpec(com.google.android.material.animation.f fVar) {
        this.v.f = fVar;
    }

    public void setExtendMotionSpecResource(int i) {
        setExtendMotionSpec(com.google.android.material.animation.f.b(getContext(), i));
    }

    public void setExtended(boolean z) {
        if (this.C == z) {
            return;
        }
        d dVar = z ? this.v : this.u;
        if (dVar.h()) {
            return;
        }
        dVar.g();
    }

    public void setHideMotionSpec(com.google.android.material.animation.f fVar) {
        this.x.f = fVar;
    }

    public void setHideMotionSpecResource(int i) {
        setHideMotionSpec(com.google.android.material.animation.f.b(getContext(), i));
    }

    @Override // android.widget.TextView, android.view.View
    public final void setPadding(int i, int i2, int i3, int i4) {
        super.setPadding(i, i2, i3, i4);
        if (!this.C || this.D) {
            return;
        }
        WeakHashMap weakHashMap = V.a;
        this.z = getPaddingStart();
        this.A = getPaddingEnd();
    }

    @Override // android.widget.TextView, android.view.View
    public final void setPaddingRelative(int i, int i2, int i3, int i4) {
        super.setPaddingRelative(i, i2, i3, i4);
        if (!this.C || this.D) {
            return;
        }
        this.z = i;
        this.A = i3;
    }

    public void setShowMotionSpec(com.google.android.material.animation.f fVar) {
        this.w.f = fVar;
    }

    public void setShowMotionSpecResource(int i) {
        setShowMotionSpec(com.google.android.material.animation.f.b(getContext(), i));
    }

    public void setShrinkMotionSpec(com.google.android.material.animation.f fVar) {
        this.u.f = fVar;
    }

    public void setShrinkMotionSpecResource(int i) {
        setShrinkMotionSpec(com.google.android.material.animation.f.b(getContext(), i));
    }

    @Override // android.widget.TextView
    public void setTextColor(int i) {
        super.setTextColor(i);
        this.F = getTextColors();
    }

    public static class ExtendedFloatingActionButtonBehavior<T extends ExtendedFloatingActionButton> extends androidx.coordinatorlayout.widget.b {
        public Rect a;
        public final boolean b;
        public final boolean c;

        public ExtendedFloatingActionButtonBehavior() {
            this.b = false;
            this.c = true;
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final /* bridge */ /* synthetic */ boolean e(Rect rect, View view) {
            return false;
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final void g(androidx.coordinatorlayout.widget.e eVar) {
            if (eVar.h == 0) {
                eVar.h = 80;
            }
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final boolean h(CoordinatorLayout coordinatorLayout, View view, View view2) {
            ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) view;
            if (view2 instanceof AppBarLayout) {
                w(coordinatorLayout, (AppBarLayout) view2, extendedFloatingActionButton);
            } else {
                ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
                if (layoutParams instanceof androidx.coordinatorlayout.widget.e ? ((androidx.coordinatorlayout.widget.e) layoutParams).a instanceof BottomSheetBehavior : false) {
                    x(view2, extendedFloatingActionButton);
                }
            }
            return false;
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final boolean l(CoordinatorLayout coordinatorLayout, View view, int i) {
            ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) view;
            ArrayList arrayListK = coordinatorLayout.k(extendedFloatingActionButton);
            int size = arrayListK.size();
            for (int i2 = 0; i2 < size; i2++) {
                View view2 = (View) arrayListK.get(i2);
                if (!(view2 instanceof AppBarLayout)) {
                    ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
                    if ((layoutParams instanceof androidx.coordinatorlayout.widget.e ? ((androidx.coordinatorlayout.widget.e) layoutParams).a instanceof BottomSheetBehavior : false) && x(view2, extendedFloatingActionButton)) {
                        break;
                    }
                } else {
                    if (w(coordinatorLayout, (AppBarLayout) view2, extendedFloatingActionButton)) {
                        break;
                    }
                }
            }
            coordinatorLayout.r(i, extendedFloatingActionButton);
            return true;
        }

        public final boolean w(CoordinatorLayout coordinatorLayout, AppBarLayout appBarLayout, ExtendedFloatingActionButton extendedFloatingActionButton) {
            androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) extendedFloatingActionButton.getLayoutParams();
            if ((!this.b && !this.c) || eVar.f != appBarLayout.getId()) {
                return false;
            }
            if (this.a == null) {
                this.a = new Rect();
            }
            Rect rect = this.a;
            com.google.android.material.internal.c.a(coordinatorLayout, appBarLayout, rect);
            if (rect.bottom <= appBarLayout.getMinimumHeightForVisibleOverlappingContent()) {
                ExtendedFloatingActionButton.e(extendedFloatingActionButton, this.c ? 2 : 1);
            } else {
                ExtendedFloatingActionButton.e(extendedFloatingActionButton, this.c ? 3 : 0);
            }
            return true;
        }

        public final boolean x(View view, ExtendedFloatingActionButton extendedFloatingActionButton) {
            androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) extendedFloatingActionButton.getLayoutParams();
            if ((!this.b && !this.c) || eVar.f != view.getId()) {
                return false;
            }
            if (view.getTop() < (extendedFloatingActionButton.getHeight() / 2) + ((ViewGroup.MarginLayoutParams) ((androidx.coordinatorlayout.widget.e) extendedFloatingActionButton.getLayoutParams())).topMargin) {
                ExtendedFloatingActionButton.e(extendedFloatingActionButton, this.c ? 2 : 1);
            } else {
                ExtendedFloatingActionButton.e(extendedFloatingActionButton, this.c ? 3 : 0);
            }
            return true;
        }

        public ExtendedFloatingActionButtonBehavior(@NonNull Context context, AttributeSet attributeSet) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.o);
            this.b = typedArrayObtainStyledAttributes.getBoolean(0, false);
            this.c = typedArrayObtainStyledAttributes.getBoolean(1, true);
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    @Override // android.widget.TextView
    public void setTextColor(@NonNull ColorStateList colorStateList) {
        super.setTextColor(colorStateList);
        this.F = getTextColors();
    }
}
