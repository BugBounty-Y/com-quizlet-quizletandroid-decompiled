package androidx.recyclerview.widget;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.GridView;
import androidx.collection.C0210h;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public class GridLayoutManager extends LinearLayoutManager {
    public static final Set P = Collections.unmodifiableSet(new HashSet(Arrays.asList(17, 66, 33, 130)));
    public boolean E;
    public int F;
    public int[] G;
    public View[] H;
    public final SparseIntArray I;
    public final SparseIntArray J;
    public final N0 K;
    public final Rect L;
    public int M;
    public int N;
    public int O;

    public GridLayoutManager(Context context, AttributeSet attributeSet, int i, int i2) {
        super(context, attributeSet, i, i2);
        this.E = false;
        this.F = -1;
        this.I = new SparseIntArray();
        this.J = new SparseIntArray();
        this.K = new N0(2);
        this.L = new Rect();
        this.M = -1;
        this.N = -1;
        this.O = -1;
        A1(AbstractC1381n0.L(context, attributeSet, i, i2).b);
    }

    public final void A1(int i) {
        if (i == this.F) {
            return;
        }
        this.E = true;
        if (i < 1) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Span count should be at least 1. Provided "));
        }
        this.F = i;
        this.K.h();
        t0();
    }

    public final void B1() {
        int iG;
        int iJ;
        if (this.p == 1) {
            iG = this.n - I();
            iJ = H();
        } else {
            iG = this.o - G();
            iJ = J();
        }
        p1(iG - iJ);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final boolean H0() {
        return this.z == null && !this.E;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void J0(B0 b0, P p, C0210h c0210h) {
        int i;
        int i2 = this.F;
        for (int i3 = 0; i3 < this.F && (i = p.d) >= 0 && i < b0.b() && i2 > 0; i3++) {
            c0210h.b(p.d, Math.max(0, p.g));
            this.K.getClass();
            i2--;
            p.d += p.e;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int M(v0 v0Var, B0 b0) {
        if (this.p == 0) {
            return Math.min(this.F, F());
        }
        if (b0.b() < 1) {
            return 0;
        }
        return w1(b0.b() - 1, v0Var, b0) + 1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:62:0x00e2, code lost:
    
        if (r13 == (r2 > r15)) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x0142, code lost:
    
        if (r16 == null) goto L86;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x0144, code lost:
    
        return r16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0145, code lost:
    
        return r17;
     */
    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View X(android.view.View r23, int r24, androidx.recyclerview.widget.v0 r25, androidx.recyclerview.widget.B0 r26) {
        /*
            Method dump skipped, instructions count: 326
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.GridLayoutManager.X(android.view.View, int, androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0):android.view.View");
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final View X0(v0 v0Var, B0 b0, boolean z, boolean z2) {
        int i;
        int iV;
        int iV2 = v();
        int i2 = 1;
        if (z2) {
            iV = v() - 1;
            i = -1;
            i2 = -1;
        } else {
            i = iV2;
            iV = 0;
        }
        int iB = b0.b();
        O0();
        int iK = this.r.k();
        int iG = this.r.g();
        View view = null;
        View view2 = null;
        while (iV != i) {
            View viewU = u(iV);
            int iK2 = AbstractC1381n0.K(viewU);
            if (iK2 >= 0 && iK2 < iB && x1(iK2, v0Var, b0) == 0) {
                if (((C1383o0) viewU.getLayoutParams()).a.isRemoved()) {
                    if (view2 == null) {
                        view2 = viewU;
                    }
                } else {
                    if (this.r.e(viewU) < iG && this.r.b(viewU) >= iK) {
                        return viewU;
                    }
                    if (view == null) {
                        view = viewU;
                    }
                }
            }
            iV += i2;
        }
        return view != null ? view : view2;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void Z(v0 v0Var, B0 b0, androidx.core.view.accessibility.e eVar) {
        super.Z(v0Var, b0, eVar);
        eVar.i(GridView.class.getName());
        AbstractC1361d0 abstractC1361d0 = this.b.m;
        if (abstractC1361d0 == null || abstractC1361d0.getItemCount() <= 1) {
            return;
        }
        eVar.b(androidx.core.view.accessibility.d.r);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void b0(v0 v0Var, B0 b0, View view, androidx.core.view.accessibility.e eVar) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (!(layoutParams instanceof E)) {
            a0(view, eVar);
            return;
        }
        E e = (E) layoutParams;
        int iW1 = w1(e.a.getLayoutPosition(), v0Var, b0);
        if (this.p == 0) {
            eVar.k(androidx.webkit.internal.p.r(e.e, e.f, iW1, 1, false));
        } else {
            eVar.k(androidx.webkit.internal.p.r(iW1, 1, e.e, e.f, false));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void c0(int i, int i2) {
        N0 n0 = this.K;
        n0.h();
        ((SparseIntArray) n0.b).clear();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void d0() {
        N0 n0 = this.K;
        n0.h();
        ((SparseIntArray) n0.b).clear();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v22 */
    /* JADX WARN: Type inference failed for: r8v23, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r8v31 */
    /* JADX WARN: Type inference failed for: r8v32 */
    /* JADX WARN: Type inference failed for: r8v37 */
    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void d1(v0 v0Var, B0 b0, P p, O o) {
        int i;
        int i2;
        int i3;
        int iD;
        int iH;
        int iJ;
        int iD2;
        int iW;
        int iW2;
        ?? r8;
        int i4;
        View viewB;
        int iJ2 = this.r.j();
        boolean z = iJ2 != 1073741824;
        int i5 = v() > 0 ? this.G[this.F] : 0;
        if (z) {
            B1();
        }
        boolean z2 = p.e == 1;
        int iX1 = this.F;
        if (!z2) {
            iX1 = x1(p.d, v0Var, b0) + y1(p.d, v0Var, b0);
        }
        int i6 = 0;
        while (i6 < this.F && (i4 = p.d) >= 0 && i4 < b0.b() && iX1 > 0) {
            int i7 = p.d;
            int iY1 = y1(i7, v0Var, b0);
            if (iY1 > this.F) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.r(android.support.v4.media.session.a.w("Item at position ", i7, " requires ", " spans but GridLayoutManager has only ", iY1), this.F, " spans."));
            }
            iX1 -= iY1;
            if (iX1 < 0 || (viewB = p.b(v0Var)) == null) {
                break;
            }
            this.H[i6] = viewB;
            i6++;
        }
        if (i6 == 0) {
            o.b = true;
            return;
        }
        if (z2) {
            i3 = 1;
            i2 = i6;
            i = 0;
        } else {
            i = i6 - 1;
            i2 = -1;
            i3 = -1;
        }
        int i8 = 0;
        while (i != i2) {
            View view = this.H[i];
            E e = (E) view.getLayoutParams();
            int iY12 = y1(AbstractC1381n0.K(view), v0Var, b0);
            e.f = iY12;
            e.e = i8;
            i8 += iY12;
            i += i3;
        }
        float f = DefinitionKt.NO_Float_VALUE;
        int i9 = 0;
        for (int i10 = 0; i10 < i6; i10++) {
            View view2 = this.H[i10];
            if (p.k != null) {
                r8 = 0;
                r8 = 0;
                if (z2) {
                    b(view2, -1, true);
                } else {
                    b(view2, 0, true);
                }
            } else if (z2) {
                r8 = 0;
                b(view2, -1, false);
            } else {
                r8 = 0;
                b(view2, 0, false);
            }
            RecyclerView recyclerView = this.b;
            Rect rect = this.L;
            if (recyclerView == null) {
                rect.set(r8, r8, r8, r8);
            } else {
                rect.set(recyclerView.Q(view2));
            }
            z1(view2, iJ2, r8);
            int iC = this.r.c(view2);
            if (iC > i9) {
                i9 = iC;
            }
            float fD = (this.r.d(view2) * 1.0f) / ((E) view2.getLayoutParams()).f;
            if (fD > f) {
                f = fD;
            }
        }
        if (z) {
            p1(Math.max(Math.round(f * this.F), i5));
            i9 = 0;
            for (int i11 = 0; i11 < i6; i11++) {
                View view3 = this.H[i11];
                z1(view3, 1073741824, true);
                int iC2 = this.r.c(view3);
                if (iC2 > i9) {
                    i9 = iC2;
                }
            }
        }
        for (int i12 = 0; i12 < i6; i12++) {
            View view4 = this.H[i12];
            if (this.r.c(view4) != i9) {
                E e2 = (E) view4.getLayoutParams();
                Rect rect2 = e2.b;
                int i13 = rect2.top + rect2.bottom + ((ViewGroup.MarginLayoutParams) e2).topMargin + ((ViewGroup.MarginLayoutParams) e2).bottomMargin;
                int i14 = rect2.left + rect2.right + ((ViewGroup.MarginLayoutParams) e2).leftMargin + ((ViewGroup.MarginLayoutParams) e2).rightMargin;
                int iV1 = v1(e2.e, e2.f);
                if (this.p == 1) {
                    iW2 = AbstractC1381n0.w(iV1, 1073741824, i14, ((ViewGroup.MarginLayoutParams) e2).width, false);
                    iW = View.MeasureSpec.makeMeasureSpec(i9 - i13, 1073741824);
                } else {
                    int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(i9 - i14, 1073741824);
                    iW = AbstractC1381n0.w(iV1, 1073741824, i13, ((ViewGroup.MarginLayoutParams) e2).height, false);
                    iW2 = iMakeMeasureSpec;
                }
                if (E0(view4, iW2, iW, (C1383o0) view4.getLayoutParams())) {
                    view4.measure(iW2, iW);
                }
            }
        }
        o.a = i9;
        if (this.p != 1) {
            if (p.f == -1) {
                int i15 = p.b;
                iH = i15 - i9;
                iD = i15;
            } else {
                int i16 = p.b;
                iD = i16 + i9;
                iH = i16;
            }
            iJ = 0;
            iD2 = 0;
        } else if (p.f == -1) {
            iD2 = p.b;
            iJ = iD2 - i9;
            iH = 0;
            iD = 0;
        } else {
            int i17 = p.b;
            iJ = i17;
            iD = 0;
            iD2 = i17 + i9;
            iH = 0;
        }
        for (int i18 = 0; i18 < i6; i18++) {
            View view5 = this.H[i18];
            E e3 = (E) view5.getLayoutParams();
            if (this.p != 1) {
                iJ = J() + this.G[e3.e];
                iD2 = this.r.d(view5) + iJ;
            } else if (c1()) {
                int iH2 = H() + this.G[this.F - e3.e];
                iD = iH2;
                iH = iH2 - this.r.d(view5);
            } else {
                iH = H() + this.G[e3.e];
                iD = this.r.d(view5) + iH;
            }
            AbstractC1381n0.R(view5, iH, iJ, iD, iD2);
            if (e3.a.isRemoved() || e3.a.isUpdated()) {
                o.c = true;
            }
            o.d = view5.hasFocusable() | o.d;
        }
        Arrays.fill(this.H, (Object) null);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void e0(int i, int i2) {
        N0 n0 = this.K;
        n0.h();
        ((SparseIntArray) n0.b).clear();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void e1(v0 v0Var, B0 b0, N n, int i) {
        B1();
        if (b0.b() > 0 && !b0.g) {
            boolean z = i == 1;
            int iX1 = x1(n.b, v0Var, b0);
            if (z) {
                while (iX1 > 0) {
                    int i2 = n.b;
                    if (i2 <= 0) {
                        break;
                    }
                    int i3 = i2 - 1;
                    n.b = i3;
                    iX1 = x1(i3, v0Var, b0);
                }
            } else {
                int iB = b0.b() - 1;
                int i4 = n.b;
                while (i4 < iB) {
                    int i5 = i4 + 1;
                    int iX12 = x1(i5, v0Var, b0);
                    if (iX12 <= iX1) {
                        break;
                    }
                    i4 = i5;
                    iX1 = iX12;
                }
                n.b = i4;
            }
        }
        q1();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean f(C1383o0 c1383o0) {
        return c1383o0 instanceof E;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void f0(int i, int i2) {
        N0 n0 = this.K;
        n0.h();
        ((SparseIntArray) n0.b).clear();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void g0(int i, int i2) {
        N0 n0 = this.K;
        n0.h();
        ((SparseIntArray) n0.b).clear();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void h0(v0 v0Var, B0 b0) {
        boolean z = b0.g;
        SparseIntArray sparseIntArray = this.J;
        SparseIntArray sparseIntArray2 = this.I;
        if (z) {
            int iV = v();
            for (int i = 0; i < iV; i++) {
                E e = (E) u(i).getLayoutParams();
                int layoutPosition = e.a.getLayoutPosition();
                sparseIntArray2.put(layoutPosition, e.f);
                sparseIntArray.put(layoutPosition, e.e);
            }
        }
        super.h0(v0Var, b0);
        sparseIntArray2.clear();
        sparseIntArray.clear();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void i0(B0 b0) {
        View viewQ;
        super.i0(b0);
        this.E = false;
        int i = this.M;
        if (i == -1 || (viewQ = q(i)) == null) {
            return;
        }
        viewQ.sendAccessibilityEvent(67108864);
        this.M = -1;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int k(B0 b0) {
        return L0(b0);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int l(B0 b0) {
        return M0(b0);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void l1(boolean z) {
        if (z) {
            throw new UnsupportedOperationException("GridLayoutManager does not support stack from end. Consider using reverse layout");
        }
        super.l1(false);
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x01a7  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x01a9 A[EDGE_INSN: B:206:0x01a9->B:122:0x01a9 BREAK  A[LOOP:2: B:126:0x01b9->B:135:0x01e2, LOOP_LABEL: LOOP:2: B:126:0x01b9->B:135:0x01e2], EDGE_INSN: B:213:0x01a9->B:122:0x01a9 BREAK  A[LOOP:5: B:148:0x0221->B:159:0x0251, LOOP_LABEL: LOOP:5: B:148:0x0221->B:159:0x0251]] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0213  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x027e  */
    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m0(int r12, android.os.Bundle r13) {
        /*
            Method dump skipped, instructions count: 729
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.GridLayoutManager.m0(int, android.os.Bundle):boolean");
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int n(B0 b0) {
        return L0(b0);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int o(B0 b0) {
        return M0(b0);
    }

    public final void p1(int i) {
        int i2;
        int[] iArr = this.G;
        int i3 = this.F;
        if (iArr == null || iArr.length != i3 + 1 || iArr[iArr.length - 1] != i) {
            iArr = new int[i3 + 1];
        }
        int i4 = 0;
        iArr[0] = 0;
        int i5 = i / i3;
        int i6 = i % i3;
        int i7 = 0;
        for (int i8 = 1; i8 <= i3; i8++) {
            i4 += i6;
            if (i4 <= 0 || i3 - i4 >= i6) {
                i2 = i5;
            } else {
                i2 = i5 + 1;
                i4 -= i3;
            }
            i7 += i2;
            iArr[i8] = i7;
        }
        this.G = iArr;
    }

    public final void q1() {
        View[] viewArr = this.H;
        if (viewArr == null || viewArr.length != this.F) {
            this.H = new View[this.F];
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 r() {
        return this.p == 0 ? new E(-2, -1) : new E(-1, -2);
    }

    public final int r1(int i) {
        if (this.p == 0) {
            RecyclerView recyclerView = this.b;
            return w1(i, recyclerView.c, recyclerView.r1);
        }
        RecyclerView recyclerView2 = this.b;
        return x1(i, recyclerView2.c, recyclerView2.r1);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 s(Context context, AttributeSet attributeSet) {
        E e = new E(context, attributeSet);
        e.e = -1;
        e.f = 0;
        return e;
    }

    public final int s1(int i) {
        if (this.p == 1) {
            RecyclerView recyclerView = this.b;
            return w1(i, recyclerView.c, recyclerView.r1);
        }
        RecyclerView recyclerView2 = this.b;
        return x1(i, recyclerView2.c, recyclerView2.r1);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 t(ViewGroup.LayoutParams layoutParams) {
        if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
            E e = new E((ViewGroup.MarginLayoutParams) layoutParams);
            e.e = -1;
            e.f = 0;
            return e;
        }
        E e2 = new E(layoutParams);
        e2.e = -1;
        e2.f = 0;
        return e2;
    }

    public final HashSet t1(int i) {
        return u1(s1(i), i);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int u0(int i, v0 v0Var, B0 b0) {
        B1();
        q1();
        return super.u0(i, v0Var, b0);
    }

    public final HashSet u1(int i, int i2) {
        HashSet hashSet = new HashSet();
        RecyclerView recyclerView = this.b;
        int iY1 = y1(i2, recyclerView.c, recyclerView.r1);
        for (int i3 = i; i3 < i + iY1; i3++) {
            hashSet.add(Integer.valueOf(i3));
        }
        return hashSet;
    }

    public final int v1(int i, int i2) {
        if (this.p != 1 || !c1()) {
            int[] iArr = this.G;
            return iArr[i2 + i] - iArr[i];
        }
        int[] iArr2 = this.G;
        int i3 = this.F;
        return iArr2[i3 - i] - iArr2[(i3 - i) - i2];
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int w0(int i, v0 v0Var, B0 b0) {
        B1();
        q1();
        return super.w0(i, v0Var, b0);
    }

    public final int w1(int i, v0 v0Var, B0 b0) {
        boolean z = b0.g;
        N0 n0 = this.K;
        if (!z) {
            int i2 = this.F;
            n0.getClass();
            return N0.g(i, i2);
        }
        int iB = v0Var.b(i);
        if (iB != -1) {
            int i3 = this.F;
            n0.getClass();
            return N0.g(iB, i3);
        }
        Log.w("GridLayoutManager", "Cannot find span size for pre layout position. " + i);
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int x(v0 v0Var, B0 b0) {
        if (this.p == 1) {
            return Math.min(this.F, F());
        }
        if (b0.b() < 1) {
            return 0;
        }
        return w1(b0.b() - 1, v0Var, b0) + 1;
    }

    public final int x1(int i, v0 v0Var, B0 b0) {
        boolean z = b0.g;
        N0 n0 = this.K;
        if (!z) {
            int i2 = this.F;
            n0.getClass();
            return i % i2;
        }
        int i3 = this.J.get(i, -1);
        if (i3 != -1) {
            return i3;
        }
        int iB = v0Var.b(i);
        if (iB != -1) {
            int i4 = this.F;
            n0.getClass();
            return iB % i4;
        }
        Log.w("GridLayoutManager", "Cannot find span size for pre layout position. It is not cached, not in the adapter. Pos:" + i);
        return 0;
    }

    public final int y1(int i, v0 v0Var, B0 b0) {
        boolean z = b0.g;
        N0 n0 = this.K;
        if (!z) {
            n0.getClass();
            return 1;
        }
        int i2 = this.I.get(i, -1);
        if (i2 != -1) {
            return i2;
        }
        if (v0Var.b(i) != -1) {
            n0.getClass();
            return 1;
        }
        Log.w("GridLayoutManager", "Cannot find span size for pre layout position. It is not cached, not in the adapter. Pos:" + i);
        return 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void z0(Rect rect, int i, int i2) {
        int iG;
        int iG2;
        if (this.G == null) {
            super.z0(rect, i, i2);
        }
        int I = I() + H();
        int iG3 = G() + J();
        if (this.p == 1) {
            int iHeight = rect.height() + iG3;
            RecyclerView recyclerView = this.b;
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            iG2 = AbstractC1381n0.g(i2, iHeight, recyclerView.getMinimumHeight());
            int[] iArr = this.G;
            iG = AbstractC1381n0.g(i, iArr[iArr.length - 1] + I, this.b.getMinimumWidth());
        } else {
            int iWidth = rect.width() + I;
            RecyclerView recyclerView2 = this.b;
            WeakHashMap weakHashMap2 = androidx.core.view.V.a;
            iG = AbstractC1381n0.g(i, iWidth, recyclerView2.getMinimumWidth());
            int[] iArr2 = this.G;
            iG2 = AbstractC1381n0.g(i2, iArr2[iArr2.length - 1] + iG3, this.b.getMinimumHeight());
        }
        this.b.setMeasuredDimension(iG, iG2);
    }

    public final void z1(View view, int i, boolean z) {
        int iW;
        int iW2;
        E e = (E) view.getLayoutParams();
        Rect rect = e.b;
        int i2 = rect.top + rect.bottom + ((ViewGroup.MarginLayoutParams) e).topMargin + ((ViewGroup.MarginLayoutParams) e).bottomMargin;
        int i3 = rect.left + rect.right + ((ViewGroup.MarginLayoutParams) e).leftMargin + ((ViewGroup.MarginLayoutParams) e).rightMargin;
        int iV1 = v1(e.e, e.f);
        if (this.p == 1) {
            iW2 = AbstractC1381n0.w(iV1, i, i3, ((ViewGroup.MarginLayoutParams) e).width, false);
            iW = AbstractC1381n0.w(this.r.l(), this.m, i2, ((ViewGroup.MarginLayoutParams) e).height, true);
        } else {
            int iW3 = AbstractC1381n0.w(iV1, i, i2, ((ViewGroup.MarginLayoutParams) e).height, false);
            int iW4 = AbstractC1381n0.w(this.r.l(), this.l, i3, ((ViewGroup.MarginLayoutParams) e).width, true);
            iW = iW3;
            iW2 = iW4;
        }
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        if (z ? E0(view, iW2, iW, c1383o0) : C0(view, iW2, iW, c1383o0)) {
            view.measure(iW2, iW);
        }
    }

    public GridLayoutManager(dagger.hilt.android.internal.managers.j jVar, int i) {
        super(jVar);
        this.E = false;
        this.F = -1;
        this.I = new SparseIntArray();
        this.J = new SparseIntArray();
        this.K = new N0(2);
        this.L = new Rect();
        this.M = -1;
        this.N = -1;
        this.O = -1;
        A1(i);
    }

    public GridLayoutManager(int i) {
        super(1);
        this.E = false;
        this.F = -1;
        this.I = new SparseIntArray();
        this.J = new SparseIntArray();
        this.K = new N0(2);
        this.L = new Rect();
        this.M = -1;
        this.N = -1;
        this.O = -1;
        A1(i);
    }
}
