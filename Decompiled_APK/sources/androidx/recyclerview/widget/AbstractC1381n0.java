package androidx.recyclerview.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.collection.C0210h;
import androidx.compose.foundation.gestures.l1;
import java.util.ArrayList;
import java.util.WeakHashMap;

/* renamed from: androidx.recyclerview.widget.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1381n0 {
    public androidx.camera.camera2.internal.concurrent.a a;
    public RecyclerView b;
    public final N0 c;
    public final N0 d;
    public S e;
    public boolean f;
    public boolean g;
    public final boolean h;
    public final boolean i;
    public int j;
    public boolean k;
    public int l;
    public int m;
    public int n;
    public int o;

    public AbstractC1381n0() {
        C1377l0 c1377l0 = new C1377l0(this, 0);
        C1377l0 c1377l02 = new C1377l0(this, 1);
        this.c = new N0(c1377l0);
        this.d = new N0(c1377l02);
        this.f = false;
        this.g = false;
        this.h = true;
        this.i = true;
    }

    public static int A(View view) {
        return view.getLeft() - ((C1383o0) view.getLayoutParams()).b.left;
    }

    public static int B(View view) {
        Rect rect = ((C1383o0) view.getLayoutParams()).b;
        return view.getMeasuredHeight() + rect.top + rect.bottom;
    }

    public static int C(View view) {
        Rect rect = ((C1383o0) view.getLayoutParams()).b;
        return view.getMeasuredWidth() + rect.left + rect.right;
    }

    public static int D(View view) {
        return view.getRight() + ((C1383o0) view.getLayoutParams()).b.right;
    }

    public static int E(View view) {
        return view.getTop() - ((C1383o0) view.getLayoutParams()).b.top;
    }

    public static int K(View view) {
        return ((C1383o0) view.getLayoutParams()).a.getLayoutPosition();
    }

    public static C1379m0 L(Context context, AttributeSet attributeSet, int i, int i2) {
        C1379m0 c1379m0 = new C1379m0();
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, androidx.recyclerview.a.a, i, i2);
        c1379m0.a = typedArrayObtainStyledAttributes.getInt(0, 1);
        c1379m0.b = typedArrayObtainStyledAttributes.getInt(10, 1);
        c1379m0.c = typedArrayObtainStyledAttributes.getBoolean(9, false);
        c1379m0.d = typedArrayObtainStyledAttributes.getBoolean(11, false);
        typedArrayObtainStyledAttributes.recycle();
        return c1379m0;
    }

    public static boolean Q(int i, int i2, int i3) {
        int mode = View.MeasureSpec.getMode(i2);
        int size = View.MeasureSpec.getSize(i2);
        if (i3 > 0 && i != i3) {
            return false;
        }
        if (mode == Integer.MIN_VALUE) {
            return size >= i;
        }
        if (mode != 0) {
            return mode == 1073741824 && size == i;
        }
        return true;
    }

    public static void R(View view, int i, int i2, int i3, int i4) {
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        Rect rect = c1383o0.b;
        view.layout(i + rect.left + ((ViewGroup.MarginLayoutParams) c1383o0).leftMargin, i2 + rect.top + ((ViewGroup.MarginLayoutParams) c1383o0).topMargin, (i3 - rect.right) - ((ViewGroup.MarginLayoutParams) c1383o0).rightMargin, (i4 - rect.bottom) - ((ViewGroup.MarginLayoutParams) c1383o0).bottomMargin);
    }

    public static int g(int i, int i2, int i3) {
        int mode = View.MeasureSpec.getMode(i);
        int size = View.MeasureSpec.getSize(i);
        return mode != Integer.MIN_VALUE ? mode != 1073741824 ? Math.max(i2, i3) : size : Math.min(size, Math.max(i2, i3));
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001a  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0022  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int w(int r4, int r5, int r6, int r7, boolean r8) {
        /*
            int r4 = r4 - r6
            r6 = 0
            int r4 = java.lang.Math.max(r6, r4)
            r0 = -2
            r1 = -1
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = 1073741824(0x40000000, float:2.0)
            if (r8 == 0) goto L1d
            if (r7 < 0) goto L12
        L10:
            r5 = r3
            goto L30
        L12:
            if (r7 != r1) goto L1a
            if (r5 == r2) goto L22
            if (r5 == 0) goto L1a
            if (r5 == r3) goto L22
        L1a:
            r5 = r6
            r7 = r5
            goto L30
        L1d:
            if (r7 < 0) goto L20
            goto L10
        L20:
            if (r7 != r1) goto L24
        L22:
            r7 = r4
            goto L30
        L24:
            if (r7 != r0) goto L1a
            if (r5 == r2) goto L2e
            if (r5 != r3) goto L2b
            goto L2e
        L2b:
            r7 = r4
            r5 = r6
            goto L30
        L2e:
            r7 = r4
            r5 = r2
        L30:
            int r4 = android.view.View.MeasureSpec.makeMeasureSpec(r7, r5)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.AbstractC1381n0.w(int, int, int, int, boolean):int");
    }

    public static int y(View view) {
        return view.getBottom() + ((C1383o0) view.getLayoutParams()).b.bottom;
    }

    public final void A0(int i, int i2) {
        int iV = v();
        if (iV == 0) {
            this.b.r(i, i2);
            return;
        }
        int i3 = Integer.MIN_VALUE;
        int i4 = Integer.MAX_VALUE;
        int i5 = Integer.MIN_VALUE;
        int i6 = Integer.MAX_VALUE;
        for (int i7 = 0; i7 < iV; i7++) {
            View viewU = u(i7);
            Rect rect = this.b.j;
            z(rect, viewU);
            int i8 = rect.left;
            if (i8 < i6) {
                i6 = i8;
            }
            int i9 = rect.right;
            if (i9 > i3) {
                i3 = i9;
            }
            int i10 = rect.top;
            if (i10 < i4) {
                i4 = i10;
            }
            int i11 = rect.bottom;
            if (i11 > i5) {
                i5 = i11;
            }
        }
        this.b.j.set(i6, i4, i3, i5);
        z0(this.b.j, i, i2);
    }

    public final void B0(RecyclerView recyclerView) {
        if (recyclerView == null) {
            this.b = null;
            this.a = null;
            this.n = 0;
            this.o = 0;
        } else {
            this.b = recyclerView;
            this.a = recyclerView.f;
            this.n = recyclerView.getWidth();
            this.o = recyclerView.getHeight();
        }
        this.l = 1073741824;
        this.m = 1073741824;
    }

    public final boolean C0(View view, int i, int i2, C1383o0 c1383o0) {
        return (!view.isLayoutRequested() && this.h && Q(view.getWidth(), i, ((ViewGroup.MarginLayoutParams) c1383o0).width) && Q(view.getHeight(), i2, ((ViewGroup.MarginLayoutParams) c1383o0).height)) ? false : true;
    }

    public boolean D0() {
        return false;
    }

    public final boolean E0(View view, int i, int i2, C1383o0 c1383o0) {
        return (this.h && Q(view.getMeasuredWidth(), i, ((ViewGroup.MarginLayoutParams) c1383o0).width) && Q(view.getMeasuredHeight(), i2, ((ViewGroup.MarginLayoutParams) c1383o0).height)) ? false : true;
    }

    public final int F() {
        RecyclerView recyclerView = this.b;
        AbstractC1361d0 adapter = recyclerView != null ? recyclerView.getAdapter() : null;
        if (adapter != null) {
            return adapter.getItemCount();
        }
        return 0;
    }

    public abstract void F0(RecyclerView recyclerView, B0 b0, int i);

    public final int G() {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            return recyclerView.getPaddingBottom();
        }
        return 0;
    }

    public final void G0(S s) {
        S s2 = this.e;
        if (s2 != null && s != s2 && s2.e) {
            s2.k();
        }
        this.e = s;
        RecyclerView recyclerView = this.b;
        s.getClass();
        E0 e0 = recyclerView.o1;
        e0.g.removeCallbacks(e0);
        e0.c.abortAnimation();
        if (s.h) {
            Log.w("RecyclerView", "An instance of " + s.getClass().getSimpleName() + " was started more than once. Each instance of" + s.getClass().getSimpleName() + " is intended to only be used once. You should create a new instance for each use.");
        }
        s.b = recyclerView;
        s.c = this;
        int i = s.a;
        if (i == -1) {
            throw new IllegalArgumentException("Invalid target position");
        }
        recyclerView.r1.a = i;
        s.e = true;
        s.d = true;
        s.f = recyclerView.n.q(i);
        s.b.o1.b();
        s.h = true;
    }

    public int H() {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            return recyclerView.getPaddingLeft();
        }
        return 0;
    }

    public boolean H0() {
        return false;
    }

    public int I() {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            return recyclerView.getPaddingRight();
        }
        return 0;
    }

    public final int J() {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            return recyclerView.getPaddingTop();
        }
        return 0;
    }

    public int M(v0 v0Var, B0 b0) {
        RecyclerView recyclerView = this.b;
        if (recyclerView == null || recyclerView.m == null || !e()) {
            return 1;
        }
        return this.b.m.getItemCount();
    }

    public final void N(Rect rect, View view) {
        Matrix matrix;
        Rect rect2 = ((C1383o0) view.getLayoutParams()).b;
        rect.set(-rect2.left, -rect2.top, view.getWidth() + rect2.right, view.getHeight() + rect2.bottom);
        if (this.b != null && (matrix = view.getMatrix()) != null && !matrix.isIdentity()) {
            RectF rectF = this.b.l;
            rectF.set(rect);
            matrix.mapRect(rectF);
            rect.set((int) Math.floor(rectF.left), (int) Math.floor(rectF.top), (int) Math.ceil(rectF.right), (int) Math.ceil(rectF.bottom));
        }
        rect.offset(view.getLeft(), view.getTop());
    }

    public abstract boolean O();

    public boolean P() {
        return false;
    }

    public void S(int i) {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            int iX = recyclerView.f.x();
            for (int i2 = 0; i2 < iX; i2++) {
                recyclerView.f.w(i2).offsetLeftAndRight(i);
            }
        }
    }

    public void T(int i) {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            int iX = recyclerView.f.x();
            for (int i2 = 0; i2 < iX; i2++) {
                recyclerView.f.w(i2).offsetTopAndBottom(i);
            }
        }
    }

    public void U() {
    }

    public void V(RecyclerView recyclerView) {
    }

    public abstract void W(RecyclerView recyclerView);

    public abstract View X(View view, int i, v0 v0Var, B0 b0);

    public void Y(AccessibilityEvent accessibilityEvent) {
        RecyclerView recyclerView = this.b;
        v0 v0Var = recyclerView.c;
        if (accessibilityEvent == null) {
            return;
        }
        boolean z = true;
        if (!recyclerView.canScrollVertically(1) && !this.b.canScrollVertically(-1) && !this.b.canScrollHorizontally(-1) && !this.b.canScrollHorizontally(1)) {
            z = false;
        }
        accessibilityEvent.setScrollable(z);
        AbstractC1361d0 abstractC1361d0 = this.b.m;
        if (abstractC1361d0 != null) {
            accessibilityEvent.setItemCount(abstractC1361d0.getItemCount());
        }
    }

    public void Z(v0 v0Var, B0 b0, androidx.core.view.accessibility.e eVar) {
        if (this.b.canScrollVertically(-1) || this.b.canScrollHorizontally(-1)) {
            eVar.a(8192);
            eVar.l(true);
            eVar.h(67108864, true);
        }
        if (this.b.canScrollVertically(1) || this.b.canScrollHorizontally(1)) {
            eVar.a(4096);
            eVar.l(true);
            eVar.h(67108864, true);
        }
        eVar.j(androidx.appcompat.app.Q.C(M(v0Var, b0), x(v0Var, b0), 0));
    }

    public final void a0(View view, androidx.core.view.accessibility.e eVar) {
        F0 f0P = RecyclerView.P(view);
        if (f0P == null || f0P.isRemoved()) {
            return;
        }
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        if (((ArrayList) aVar.c).contains(f0P.itemView)) {
            return;
        }
        RecyclerView recyclerView = this.b;
        b0(recyclerView.c, recyclerView.r1, view, eVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00ea  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.view.View r9, int r10, boolean r11) {
        /*
            Method dump skipped, instructions count: 342
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.AbstractC1381n0.b(android.view.View, int, boolean):void");
    }

    public void b0(v0 v0Var, B0 b0, View view, androidx.core.view.accessibility.e eVar) {
        eVar.k(androidx.webkit.internal.p.r(e() ? K(view) : 0, 1, d() ? K(view) : 0, 1, false));
    }

    public void c(String str) {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            recyclerView.l(str);
        }
    }

    public void c0(int i, int i2) {
    }

    public abstract boolean d();

    public void d0() {
    }

    public abstract boolean e();

    public void e0(int i, int i2) {
    }

    public boolean f(C1383o0 c1383o0) {
        return c1383o0 != null;
    }

    public void f0(int i, int i2) {
    }

    public void g0(int i, int i2) {
    }

    public void h(int i, int i2, B0 b0, C0210h c0210h) {
    }

    public abstract void h0(v0 v0Var, B0 b0);

    public void i(int i, C0210h c0210h) {
    }

    public abstract void i0(B0 b0);

    public abstract int j(B0 b0);

    public void j0(Parcelable parcelable) {
    }

    public abstract int k(B0 b0);

    public Parcelable k0() {
        return null;
    }

    public abstract int l(B0 b0);

    public void l0(int i) {
    }

    public abstract int m(B0 b0);

    public boolean m0(int i, Bundle bundle) {
        RecyclerView recyclerView = this.b;
        return n0(recyclerView.c, recyclerView.r1, i, bundle);
    }

    public abstract int n(B0 b0);

    /* JADX WARN: Removed duplicated region for block: B:21:0x0062 A[PHI: r8
  0x0062: PHI (r8v8 int) = (r8v5 int), (r8v18 int) binds: [B:27:0x007e, B:19:0x0054] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00ba  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00d3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean n0(androidx.recyclerview.widget.v0 r8, androidx.recyclerview.widget.B0 r9, int r10, android.os.Bundle r11) {
        /*
            Method dump skipped, instructions count: 235
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.AbstractC1381n0.n0(androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0, int, android.os.Bundle):boolean");
    }

    public abstract int o(B0 b0);

    public final void o0(v0 v0Var) {
        for (int iV = v() - 1; iV >= 0; iV--) {
            if (!RecyclerView.P(u(iV)).shouldIgnore()) {
                View viewU = u(iV);
                r0(iV);
                v0Var.h(viewU);
            }
        }
    }

    public final void p(v0 v0Var) {
        for (int iV = v() - 1; iV >= 0; iV--) {
            View viewU = u(iV);
            F0 f0P = RecyclerView.P(viewU);
            if (f0P.shouldIgnore()) {
                if (RecyclerView.N1) {
                    f0P.toString();
                }
            } else if (!f0P.isInvalid() || f0P.isRemoved() || this.b.m.hasStableIds()) {
                u(iV);
                this.a.p(iV);
                v0Var.j(viewU);
                this.b.g.m(f0P);
            } else {
                r0(iV);
                v0Var.i(f0P);
            }
        }
    }

    public final void p0(v0 v0Var) {
        ArrayList arrayList;
        int size = v0Var.a.size();
        int i = size - 1;
        while (true) {
            arrayList = v0Var.a;
            if (i < 0) {
                break;
            }
            View view = ((F0) arrayList.get(i)).itemView;
            F0 f0P = RecyclerView.P(view);
            if (!f0P.shouldIgnore()) {
                f0P.setIsRecyclable(false);
                if (f0P.isTmpDetached()) {
                    this.b.removeDetachedView(view, false);
                }
                AbstractC1373j0 abstractC1373j0 = this.b.M;
                if (abstractC1373j0 != null) {
                    abstractC1373j0.d(f0P);
                }
                f0P.setIsRecyclable(true);
                F0 f0P2 = RecyclerView.P(view);
                f0P2.mScrapContainer = null;
                f0P2.mInChangeScrap = false;
                f0P2.clearReturnedFromScrapFlag();
                v0Var.i(f0P2);
            }
            i--;
        }
        arrayList.clear();
        ArrayList arrayList2 = v0Var.b;
        if (arrayList2 != null) {
            arrayList2.clear();
        }
        if (size > 0) {
            this.b.invalidate();
        }
    }

    public View q(int i) {
        int iV = v();
        for (int i2 = 0; i2 < iV; i2++) {
            View viewU = u(i2);
            F0 f0P = RecyclerView.P(viewU);
            if (f0P != null && f0P.getLayoutPosition() == i && !f0P.shouldIgnore() && (this.b.r1.g || !f0P.isRemoved())) {
                return viewU;
            }
        }
        return null;
    }

    public final void q0(View view, v0 v0Var) {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        C1357b0 c1357b0 = (C1357b0) aVar.d;
        int i = aVar.b;
        if (i == 1) {
            throw new IllegalStateException("Cannot call removeView(At) within removeView(At)");
        }
        if (i == 2) {
            throw new IllegalStateException("Cannot call removeView(At) within removeViewIfHidden");
        }
        try {
            aVar.b = 1;
            aVar.f = view;
            int iIndexOfChild = c1357b0.a.indexOfChild(view);
            if (iIndexOfChild >= 0) {
                if (((l1) aVar.e).F(iIndexOfChild)) {
                    aVar.S(view);
                }
                c1357b0.h(iIndexOfChild);
            }
            aVar.b = 0;
            aVar.f = null;
            v0Var.h(view);
        } catch (Throwable th) {
            aVar.b = 0;
            aVar.f = null;
            throw th;
        }
    }

    public abstract C1383o0 r();

    public final void r0(int i) {
        if (u(i) != null) {
            androidx.camera.camera2.internal.concurrent.a aVar = this.a;
            C1357b0 c1357b0 = (C1357b0) aVar.d;
            int i2 = aVar.b;
            if (i2 == 1) {
                throw new IllegalStateException("Cannot call removeView(At) within removeView(At)");
            }
            if (i2 == 2) {
                throw new IllegalStateException("Cannot call removeView(At) within removeViewIfHidden");
            }
            try {
                int iY = aVar.y(i);
                View childAt = c1357b0.a.getChildAt(iY);
                if (childAt != null) {
                    aVar.b = 1;
                    aVar.f = childAt;
                    if (((l1) aVar.e).F(iY)) {
                        aVar.S(childAt);
                    }
                    c1357b0.h(iY);
                }
                aVar.b = 0;
                aVar.f = null;
            } catch (Throwable th) {
                aVar.b = 0;
                aVar.f = null;
                throw th;
            }
        }
    }

    public C1383o0 s(Context context, AttributeSet attributeSet) {
        return new C1383o0(context, attributeSet);
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x00b0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean s0(androidx.recyclerview.widget.RecyclerView r9, android.view.View r10, android.graphics.Rect r11, boolean r12, boolean r13) {
        /*
            r8 = this;
            int r0 = r8.H()
            int r1 = r8.J()
            int r2 = r8.n
            int r3 = r8.I()
            int r2 = r2 - r3
            int r3 = r8.o
            int r4 = r8.G()
            int r3 = r3 - r4
            int r4 = r10.getLeft()
            int r5 = r11.left
            int r4 = r4 + r5
            int r5 = r10.getScrollX()
            int r4 = r4 - r5
            int r5 = r10.getTop()
            int r6 = r11.top
            int r5 = r5 + r6
            int r10 = r10.getScrollY()
            int r5 = r5 - r10
            int r10 = r11.width()
            int r10 = r10 + r4
            int r11 = r11.height()
            int r11 = r11 + r5
            int r4 = r4 - r0
            r0 = 0
            int r6 = java.lang.Math.min(r0, r4)
            int r5 = r5 - r1
            int r1 = java.lang.Math.min(r0, r5)
            int r10 = r10 - r2
            int r2 = java.lang.Math.max(r0, r10)
            int r11 = r11 - r3
            int r11 = java.lang.Math.max(r0, r11)
            androidx.recyclerview.widget.RecyclerView r3 = r8.b
            int r3 = r3.getLayoutDirection()
            r7 = 1
            if (r3 != r7) goto L5e
            if (r2 == 0) goto L59
            goto L66
        L59:
            int r2 = java.lang.Math.max(r6, r10)
            goto L66
        L5e:
            if (r6 == 0) goto L61
            goto L65
        L61:
            int r6 = java.lang.Math.min(r4, r2)
        L65:
            r2 = r6
        L66:
            if (r1 == 0) goto L69
            goto L6d
        L69:
            int r1 = java.lang.Math.min(r5, r11)
        L6d:
            int[] r10 = new int[]{r2, r1}
            r11 = r10[r0]
            r10 = r10[r7]
            if (r13 == 0) goto Lb0
            android.view.View r13 = r9.getFocusedChild()
            if (r13 != 0) goto L7e
            goto Lb5
        L7e:
            int r1 = r8.H()
            int r2 = r8.J()
            int r3 = r8.n
            int r4 = r8.I()
            int r3 = r3 - r4
            int r4 = r8.o
            int r5 = r8.G()
            int r4 = r4 - r5
            androidx.recyclerview.widget.RecyclerView r5 = r8.b
            android.graphics.Rect r5 = r5.j
            r8.z(r5, r13)
            int r13 = r5.left
            int r13 = r13 - r11
            if (r13 >= r3) goto Lb5
            int r13 = r5.right
            int r13 = r13 - r11
            if (r13 <= r1) goto Lb5
            int r13 = r5.top
            int r13 = r13 - r10
            if (r13 >= r4) goto Lb5
            int r13 = r5.bottom
            int r13 = r13 - r10
            if (r13 > r2) goto Lb0
            goto Lb5
        Lb0:
            if (r11 != 0) goto Lb6
            if (r10 == 0) goto Lb5
            goto Lb6
        Lb5:
            return r0
        Lb6:
            if (r12 == 0) goto Lbc
            r9.scrollBy(r11, r10)
            return r7
        Lbc:
            r9.m0(r11, r10, r0)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.AbstractC1381n0.s0(androidx.recyclerview.widget.RecyclerView, android.view.View, android.graphics.Rect, boolean, boolean):boolean");
    }

    public C1383o0 t(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof C1383o0 ? new C1383o0((C1383o0) layoutParams) : layoutParams instanceof ViewGroup.MarginLayoutParams ? new C1383o0((ViewGroup.MarginLayoutParams) layoutParams) : new C1383o0(layoutParams);
    }

    public final void t0() {
        RecyclerView recyclerView = this.b;
        if (recyclerView != null) {
            recyclerView.requestLayout();
        }
    }

    public final View u(int i) {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        if (aVar != null) {
            return aVar.w(i);
        }
        return null;
    }

    public abstract int u0(int i, v0 v0Var, B0 b0);

    public final int v() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        if (aVar != null) {
            return aVar.x();
        }
        return 0;
    }

    public abstract void v0(int i);

    public abstract int w0(int i, v0 v0Var, B0 b0);

    public int x(v0 v0Var, B0 b0) {
        RecyclerView recyclerView = this.b;
        if (recyclerView == null || recyclerView.m == null || !d()) {
            return 1;
        }
        return this.b.m.getItemCount();
    }

    public final void x0(RecyclerView recyclerView) {
        y0(View.MeasureSpec.makeMeasureSpec(recyclerView.getWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(recyclerView.getHeight(), 1073741824));
    }

    public final void y0(int i, int i2) {
        this.n = View.MeasureSpec.getSize(i);
        int mode = View.MeasureSpec.getMode(i);
        this.l = mode;
        if (mode == 0 && !RecyclerView.Q1) {
            this.n = 0;
        }
        this.o = View.MeasureSpec.getSize(i2);
        int mode2 = View.MeasureSpec.getMode(i2);
        this.m = mode2;
        if (mode2 != 0 || RecyclerView.Q1) {
            return;
        }
        this.o = 0;
    }

    public void z(Rect rect, View view) {
        boolean z = RecyclerView.M1;
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        Rect rect2 = c1383o0.b;
        rect.set((view.getLeft() - rect2.left) - ((ViewGroup.MarginLayoutParams) c1383o0).leftMargin, (view.getTop() - rect2.top) - ((ViewGroup.MarginLayoutParams) c1383o0).topMargin, view.getRight() + rect2.right + ((ViewGroup.MarginLayoutParams) c1383o0).rightMargin, view.getBottom() + rect2.bottom + ((ViewGroup.MarginLayoutParams) c1383o0).bottomMargin);
    }

    public void z0(Rect rect, int i, int i2) {
        int I = I() + H() + rect.width();
        int iG = G() + J() + rect.height();
        RecyclerView recyclerView = this.b;
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        this.b.setMeasuredDimension(g(i, I, recyclerView.getMinimumWidth()), g(i2, iG, this.b.getMinimumHeight()));
    }
}
