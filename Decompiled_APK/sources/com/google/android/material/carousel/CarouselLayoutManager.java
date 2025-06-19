package com.google.android.material.carousel;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PointF;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import androidx.camera.view.d;
import androidx.compose.animation.f0;
import androidx.recyclerview.widget.A0;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.C1383o0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.Z;
import androidx.recyclerview.widget.v0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public class CarouselLayoutManager extends AbstractC1381n0 implements A0 {
    public final f0 p;
    public androidx.sqlite.db.b q;
    public final View.OnLayoutChangeListener r;

    public CarouselLayoutManager() {
        f0 f0Var = new f0(4);
        new a();
        this.r = new d(this, 1);
        this.p = f0Var;
        t0();
        K0(0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void F0(RecyclerView recyclerView, B0 b0, int i) {
        Z z = new Z(2, recyclerView.getContext(), this);
        z.a = i;
        G0(z);
    }

    public final boolean I0() {
        return this.q.b == 0;
    }

    public final boolean J0() {
        return I0() && this.b.getLayoutDirection() == 1;
    }

    public final void K0(int i) {
        b bVar;
        if (i != 0 && i != 1) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "invalid orientation:"));
        }
        c(null);
        androidx.sqlite.db.b bVar2 = this.q;
        if (bVar2 == null || i != bVar2.b) {
            if (i == 0) {
                bVar = new b(this, 1);
            } else {
                if (i != 1) {
                    throw new IllegalArgumentException("invalid orientation");
                }
                bVar = new b(this, 0);
            }
            this.q = bVar;
            t0();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean O() {
        return true;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void V(RecyclerView recyclerView) throws Resources.NotFoundException {
        f0 f0Var = this.p;
        Context context = recyclerView.getContext();
        float dimension = f0Var.b;
        if (dimension <= DefinitionKt.NO_Float_VALUE) {
            dimension = context.getResources().getDimension(R.dimen.m3_carousel_small_item_size_min);
        }
        f0Var.b = dimension;
        float dimension2 = f0Var.c;
        if (dimension2 <= DefinitionKt.NO_Float_VALUE) {
            dimension2 = context.getResources().getDimension(R.dimen.m3_carousel_small_item_size_max);
        }
        f0Var.c = dimension2;
        t0();
        recyclerView.addOnLayoutChangeListener(this.r);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void W(RecyclerView recyclerView) {
        recyclerView.removeOnLayoutChangeListener(this.r);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0025  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0029  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0033  */
    @Override // androidx.recyclerview.widget.AbstractC1381n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View X(android.view.View r4, int r5, androidx.recyclerview.widget.v0 r6, androidx.recyclerview.widget.B0 r7) {
        /*
            r3 = this;
            int r6 = r3.v()
            if (r6 != 0) goto L8
            goto L83
        L8:
            androidx.sqlite.db.b r6 = r3.q
            int r6 = r6.b
            r7 = -2147483648(0xffffffff80000000, float:-0.0)
            r0 = -1
            r1 = 1
            if (r5 == r1) goto L33
            r2 = 2
            if (r5 == r2) goto L29
            r2 = 17
            if (r5 == r2) goto L38
            r2 = 33
            if (r5 == r2) goto L35
            r2 = 66
            if (r5 == r2) goto L2b
            r2 = 130(0x82, float:1.82E-43)
            if (r5 == r2) goto L27
        L25:
            r5 = r7
            goto L41
        L27:
            if (r6 != r1) goto L25
        L29:
            r5 = r1
            goto L41
        L2b:
            if (r6 != 0) goto L25
            boolean r5 = r3.J0()
            if (r5 == 0) goto L29
        L33:
            r5 = r0
            goto L41
        L35:
            if (r6 != r1) goto L25
            goto L33
        L38:
            if (r6 != 0) goto L25
            boolean r5 = r3.J0()
            if (r5 == 0) goto L33
            goto L29
        L41:
            if (r5 != r7) goto L44
            goto L83
        L44:
            r6 = 0
            if (r5 != r0) goto L78
            int r4 = androidx.recyclerview.widget.AbstractC1381n0.K(r4)
            if (r4 != 0) goto L4e
            goto L83
        L4e:
            android.view.View r4 = r3.u(r6)
            int r4 = androidx.recyclerview.widget.AbstractC1381n0.K(r4)
            int r4 = r4 - r1
            if (r4 < 0) goto L67
            int r5 = r3.F()
            if (r4 < r5) goto L60
            goto L67
        L60:
            androidx.sqlite.db.b r4 = r3.q
            r4.e()
            r4 = 0
            throw r4
        L67:
            boolean r4 = r3.J0()
            if (r4 == 0) goto L73
            int r4 = r3.v()
            int r6 = r4 + (-1)
        L73:
            android.view.View r4 = r3.u(r6)
            return r4
        L78:
            int r4 = androidx.recyclerview.widget.AbstractC1381n0.K(r4)
            int r5 = r3.F()
            int r5 = r5 - r1
            if (r4 != r5) goto L85
        L83:
            r4 = 0
            return r4
        L85:
            int r4 = r3.v()
            int r4 = r4 - r1
            android.view.View r4 = r3.u(r4)
            int r4 = androidx.recyclerview.widget.AbstractC1381n0.K(r4)
            int r4 = r4 + r1
            if (r4 < 0) goto La3
            int r5 = r3.F()
            if (r4 < r5) goto L9c
            goto La3
        L9c:
            androidx.sqlite.db.b r4 = r3.q
            r4.e()
            r4 = 0
            throw r4
        La3:
            boolean r4 = r3.J0()
            if (r4 == 0) goto Laa
            goto Lb0
        Laa:
            int r4 = r3.v()
            int r6 = r4 + (-1)
        Lb0:
            android.view.View r4 = r3.u(r6)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.carousel.CarouselLayoutManager.X(android.view.View, int, androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0):android.view.View");
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void Y(AccessibilityEvent accessibilityEvent) {
        super.Y(accessibilityEvent);
        if (v() > 0) {
            accessibilityEvent.setFromIndex(AbstractC1381n0.K(u(0)));
            accessibilityEvent.setToIndex(AbstractC1381n0.K(u(v() - 1)));
        }
    }

    @Override // androidx.recyclerview.widget.A0
    public final PointF a(int i) {
        return null;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void c0(int i, int i2) {
        F();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean d() {
        return I0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean e() {
        return !I0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void f0(int i, int i2) {
        F();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void h0(v0 v0Var, B0 b0) {
        if (b0.b() > 0) {
            if ((I0() ? this.n : this.o) > DefinitionKt.NO_Float_VALUE) {
                J0();
                View view = v0Var.k(0, Long.MAX_VALUE).itemView;
                throw new IllegalStateException("All children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup.");
            }
        }
        o0(v0Var);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void i0(B0 b0) {
        if (v() == 0) {
            return;
        }
        AbstractC1381n0.K(u(0));
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int j(B0 b0) {
        v();
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int k(B0 b0) {
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int l(B0 b0) {
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int m(B0 b0) {
        v();
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int n(B0 b0) {
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int o(B0 b0) {
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 r() {
        return new C1383o0(-2, -2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean s0(RecyclerView recyclerView, View view, Rect rect, boolean z, boolean z2) {
        return false;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int u0(int i, v0 v0Var, B0 b0) {
        if (!I0() || v() == 0 || i == 0) {
            return 0;
        }
        View view = v0Var.k(0, Long.MAX_VALUE).itemView;
        throw new IllegalStateException("All children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup.");
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void v0(int i) {
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int w0(int i, v0 v0Var, B0 b0) {
        if (!e() || v() == 0 || i == 0) {
            return 0;
        }
        View view = v0Var.k(0, Long.MAX_VALUE).itemView;
        throw new IllegalStateException("All children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup.");
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void z(Rect rect, View view) {
        super.z(rect, view);
        rect.centerY();
        if (I0()) {
            rect.centerX();
        }
        throw null;
    }

    @SuppressLint({"UnknownNullness"})
    public CarouselLayoutManager(Context context, AttributeSet attributeSet, int i, int i2) {
        new a();
        this.r = new d(this, 1);
        this.p = new f0(4);
        t0();
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.g);
            typedArrayObtainStyledAttributes.getInt(0, 0);
            t0();
            K0(typedArrayObtainStyledAttributes.getInt(0, 0));
            typedArrayObtainStyledAttributes.recycle();
        }
    }
}
