package androidx.recyclerview.widget;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Rect;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.collection.C0210h;
import androidx.collection.C0220s;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public class StaggeredGridLayoutManager extends AbstractC1381n0 implements A0 {
    public final N0 B;
    public final int C;
    public boolean D;
    public boolean E;
    public SavedState F;
    public final Rect G;
    public final K0 H;
    public final boolean I;
    public int[] J;
    public final RunnableC1396y K;
    public final int p;
    public final C0220s[] q;
    public final androidx.emoji2.text.g r;
    public final androidx.emoji2.text.g s;
    public final int t;
    public int u;
    public final M v;
    public boolean w;
    public final BitSet y;
    public boolean x = false;
    public int z = -1;
    public int A = Integer.MIN_VALUE;

    @SuppressLint({"BanParcelableUsage"})
    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new O0();
        public int a;
        public int b;
        public int c;
        public int[] d;
        public int e;
        public int[] f;
        public ArrayList g;
        public boolean h;
        public boolean i;
        public boolean j;

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.a);
            parcel.writeInt(this.b);
            parcel.writeInt(this.c);
            if (this.c > 0) {
                parcel.writeIntArray(this.d);
            }
            parcel.writeInt(this.e);
            if (this.e > 0) {
                parcel.writeIntArray(this.f);
            }
            parcel.writeInt(this.h ? 1 : 0);
            parcel.writeInt(this.i ? 1 : 0);
            parcel.writeInt(this.j ? 1 : 0);
            parcel.writeList(this.g);
        }
    }

    public StaggeredGridLayoutManager(Context context, AttributeSet attributeSet, int i, int i2) {
        this.p = -1;
        this.w = false;
        N0 n0 = new N0();
        this.B = n0;
        this.C = 2;
        this.G = new Rect();
        this.H = new K0(this);
        this.I = true;
        this.K = new RunnableC1396y(this, 2);
        C1379m0 c1379m0L = AbstractC1381n0.L(context, attributeSet, i, i2);
        int i3 = c1379m0L.a;
        if (i3 != 0 && i3 != 1) {
            throw new IllegalArgumentException("invalid orientation.");
        }
        c(null);
        if (i3 != this.t) {
            this.t = i3;
            androidx.emoji2.text.g gVar = this.r;
            this.r = this.s;
            this.s = gVar;
            t0();
        }
        int i4 = c1379m0L.b;
        c(null);
        if (i4 != this.p) {
            n0.d();
            t0();
            this.p = i4;
            this.y = new BitSet(this.p);
            this.q = new C0220s[this.p];
            for (int i5 = 0; i5 < this.p; i5++) {
                this.q[i5] = new C0220s(this, i5);
            }
            t0();
        }
        boolean z = c1379m0L.c;
        c(null);
        SavedState savedState = this.F;
        if (savedState != null && savedState.h != z) {
            savedState.h = z;
        }
        this.w = z;
        t0();
        M m = new M();
        m.a = true;
        m.f = 0;
        m.g = 0;
        this.v = m;
        this.r = androidx.emoji2.text.g.a(this, this.t);
        this.s = androidx.emoji2.text.g.a(this, 1 - this.t);
    }

    public static int k1(int i, int i2, int i3) {
        int mode;
        return (!(i2 == 0 && i3 == 0) && ((mode = View.MeasureSpec.getMode(i)) == Integer.MIN_VALUE || mode == 1073741824)) ? View.MeasureSpec.makeMeasureSpec(Math.max(0, (View.MeasureSpec.getSize(i) - i2) - i3), mode) : i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void F0(RecyclerView recyclerView, B0 b0, int i) {
        S s = new S(recyclerView.getContext());
        s.a = i;
        G0(s);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean H0() {
        return this.F == null;
    }

    public final boolean I0() {
        int iR0;
        if (v() != 0 && this.C != 0 && this.g) {
            if (this.x) {
                iR0 = S0();
                R0();
            } else {
                iR0 = R0();
                S0();
            }
            N0 n0 = this.B;
            if (iR0 == 0 && W0() != null) {
                n0.d();
                this.f = true;
                t0();
                return true;
            }
        }
        return false;
    }

    public final int J0(B0 b0) {
        if (v() == 0) {
            return 0;
        }
        androidx.emoji2.text.g gVar = this.r;
        boolean z = !this.I;
        return AbstractC1358c.d(b0, gVar, O0(z), N0(z), this, this.I);
    }

    public final int K0(B0 b0) {
        if (v() == 0) {
            return 0;
        }
        androidx.emoji2.text.g gVar = this.r;
        boolean z = !this.I;
        return AbstractC1358c.e(b0, gVar, O0(z), N0(z), this, this.I, this.x);
    }

    public final int L0(B0 b0) {
        if (v() == 0) {
            return 0;
        }
        androidx.emoji2.text.g gVar = this.r;
        boolean z = !this.I;
        return AbstractC1358c.f(b0, gVar, O0(z), N0(z), this, this.I);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int M(v0 v0Var, B0 b0) {
        if (this.t == 0) {
            return Math.min(this.p, b0.b());
        }
        return -1;
    }

    /* JADX WARN: Type inference failed for: r6v20 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [boolean, int] */
    public final int M0(v0 v0Var, M m, B0 b0) {
        C0220s c0220s;
        ?? r6;
        int i;
        int iJ;
        int iC;
        int iK;
        int iC2;
        int i2;
        int i3;
        int i4;
        int i5 = 0;
        int i6 = 1;
        this.y.set(0, this.p, true);
        M m2 = this.v;
        int i7 = m2.i ? m.e == 1 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : Integer.MIN_VALUE : m.e == 1 ? m.g + m.b : m.f - m.b;
        int i8 = m.e;
        for (int i9 = 0; i9 < this.p; i9++) {
            if (!((ArrayList) this.q[i9].f).isEmpty()) {
                j1(this.q[i9], i8, i7);
            }
        }
        int iG = this.x ? this.r.g() : this.r.k();
        boolean z = false;
        while (true) {
            int i10 = m.c;
            if (((i10 < 0 || i10 >= b0.b()) ? i5 : i6) == 0 || (!m2.i && this.y.isEmpty())) {
                break;
            }
            View view = v0Var.k(m.c, Long.MAX_VALUE).itemView;
            m.c += m.d;
            L0 l0 = (L0) view.getLayoutParams();
            int layoutPosition = l0.a.getLayoutPosition();
            N0 n0 = this.B;
            int[] iArr = (int[]) n0.a;
            int i11 = (iArr == null || layoutPosition >= iArr.length) ? -1 : iArr[layoutPosition];
            if (i11 == -1) {
                if (a1(m.e)) {
                    i4 = this.p - i6;
                    i3 = -1;
                    i2 = -1;
                } else {
                    i2 = i6;
                    i3 = this.p;
                    i4 = i5;
                }
                C0220s c0220s2 = null;
                if (m.e == i6) {
                    int iK2 = this.r.k();
                    int i12 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                    while (i4 != i3) {
                        C0220s c0220s3 = this.q[i4];
                        int iH = c0220s3.h(iK2);
                        if (iH < i12) {
                            i12 = iH;
                            c0220s2 = c0220s3;
                        }
                        i4 += i2;
                    }
                } else {
                    int iG2 = this.r.g();
                    int i13 = Integer.MIN_VALUE;
                    while (i4 != i3) {
                        C0220s c0220s4 = this.q[i4];
                        int iJ2 = c0220s4.j(iG2);
                        if (iJ2 > i13) {
                            c0220s2 = c0220s4;
                            i13 = iJ2;
                        }
                        i4 += i2;
                    }
                }
                c0220s = c0220s2;
                n0.e(layoutPosition);
                ((int[]) n0.a)[layoutPosition] = c0220s.e;
            } else {
                c0220s = this.q[i11];
            }
            l0.e = c0220s;
            if (m.e == 1) {
                r6 = 0;
                b(view, -1, false);
            } else {
                r6 = 0;
                b(view, 0, false);
            }
            if (this.t == 1) {
                i = 1;
                Y0(view, AbstractC1381n0.w(this.u, this.l, r6, ((ViewGroup.MarginLayoutParams) l0).width, r6), AbstractC1381n0.w(this.o, this.m, G() + J(), ((ViewGroup.MarginLayoutParams) l0).height, true));
            } else {
                i = 1;
                Y0(view, AbstractC1381n0.w(this.n, this.l, I() + H(), ((ViewGroup.MarginLayoutParams) l0).width, true), AbstractC1381n0.w(this.u, this.m, 0, ((ViewGroup.MarginLayoutParams) l0).height, false));
            }
            if (m.e == i) {
                iC = c0220s.h(iG);
                iJ = this.r.c(view) + iC;
            } else {
                iJ = c0220s.j(iG);
                iC = iJ - this.r.c(view);
            }
            if (m.e == 1) {
                C0220s c0220s5 = l0.e;
                c0220s5.getClass();
                L0 l02 = (L0) view.getLayoutParams();
                l02.e = c0220s5;
                ArrayList arrayList = (ArrayList) c0220s5.f;
                arrayList.add(view);
                c0220s5.c = Integer.MIN_VALUE;
                if (arrayList.size() == 1) {
                    c0220s5.b = Integer.MIN_VALUE;
                }
                if (l02.a.isRemoved() || l02.a.isUpdated()) {
                    c0220s5.d = ((StaggeredGridLayoutManager) c0220s5.g).r.c(view) + c0220s5.d;
                }
            } else {
                C0220s c0220s6 = l0.e;
                c0220s6.getClass();
                L0 l03 = (L0) view.getLayoutParams();
                l03.e = c0220s6;
                ArrayList arrayList2 = (ArrayList) c0220s6.f;
                arrayList2.add(0, view);
                c0220s6.b = Integer.MIN_VALUE;
                if (arrayList2.size() == 1) {
                    c0220s6.c = Integer.MIN_VALUE;
                }
                if (l03.a.isRemoved() || l03.a.isUpdated()) {
                    c0220s6.d = ((StaggeredGridLayoutManager) c0220s6.g).r.c(view) + c0220s6.d;
                }
            }
            if (X0() && this.t == 1) {
                iC2 = this.s.g() - (((this.p - 1) - c0220s.e) * this.u);
                iK = iC2 - this.s.c(view);
            } else {
                iK = this.s.k() + (c0220s.e * this.u);
                iC2 = this.s.c(view) + iK;
            }
            if (this.t == 1) {
                AbstractC1381n0.R(view, iK, iC, iC2, iJ);
            } else {
                AbstractC1381n0.R(view, iC, iK, iJ, iC2);
            }
            j1(c0220s, m2.e, i7);
            c1(v0Var, m2);
            if (m2.h && view.hasFocusable()) {
                this.y.set(c0220s.e, false);
            }
            i6 = 1;
            z = true;
            i5 = 0;
        }
        if (!z) {
            c1(v0Var, m2);
        }
        int iK3 = m2.e == -1 ? this.r.k() - U0(this.r.k()) : T0(this.r.g()) - this.r.g();
        if (iK3 > 0) {
            return Math.min(m.b, iK3);
        }
        return 0;
    }

    public final View N0(boolean z) {
        int iK = this.r.k();
        int iG = this.r.g();
        View view = null;
        for (int iV = v() - 1; iV >= 0; iV--) {
            View viewU = u(iV);
            int iE = this.r.e(viewU);
            int iB = this.r.b(viewU);
            if (iB > iK && iE < iG) {
                if (iB <= iG || !z) {
                    return viewU;
                }
                if (view == null) {
                    view = viewU;
                }
            }
        }
        return view;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean O() {
        return this.C != 0;
    }

    public final View O0(boolean z) {
        int iK = this.r.k();
        int iG = this.r.g();
        int iV = v();
        View view = null;
        for (int i = 0; i < iV; i++) {
            View viewU = u(i);
            int iE = this.r.e(viewU);
            if (this.r.b(viewU) > iK && iE < iG) {
                if (iE >= iK || !z) {
                    return viewU;
                }
                if (view == null) {
                    view = viewU;
                }
            }
        }
        return view;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean P() {
        return this.w;
    }

    public final void P0(v0 v0Var, B0 b0, boolean z) {
        int iG;
        int iT0 = T0(Integer.MIN_VALUE);
        if (iT0 != Integer.MIN_VALUE && (iG = this.r.g() - iT0) > 0) {
            int i = iG - (-g1(-iG, v0Var, b0));
            if (!z || i <= 0) {
                return;
            }
            this.r.o(i);
        }
    }

    public final void Q0(v0 v0Var, B0 b0, boolean z) {
        int iK;
        int iU0 = U0(SubsamplingScaleImageView.TILE_SIZE_AUTO);
        if (iU0 != Integer.MAX_VALUE && (iK = iU0 - this.r.k()) > 0) {
            int iG1 = iK - g1(iK, v0Var, b0);
            if (!z || iG1 <= 0) {
                return;
            }
            this.r.o(-iG1);
        }
    }

    public final int R0() {
        if (v() == 0) {
            return 0;
        }
        return AbstractC1381n0.K(u(0));
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void S(int i) {
        super.S(i);
        for (int i2 = 0; i2 < this.p; i2++) {
            C0220s c0220s = this.q[i2];
            int i3 = c0220s.b;
            if (i3 != Integer.MIN_VALUE) {
                c0220s.b = i3 + i;
            }
            int i4 = c0220s.c;
            if (i4 != Integer.MIN_VALUE) {
                c0220s.c = i4 + i;
            }
        }
    }

    public final int S0() {
        int iV = v();
        if (iV == 0) {
            return 0;
        }
        return AbstractC1381n0.K(u(iV - 1));
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void T(int i) {
        super.T(i);
        for (int i2 = 0; i2 < this.p; i2++) {
            C0220s c0220s = this.q[i2];
            int i3 = c0220s.b;
            if (i3 != Integer.MIN_VALUE) {
                c0220s.b = i3 + i;
            }
            int i4 = c0220s.c;
            if (i4 != Integer.MIN_VALUE) {
                c0220s.c = i4 + i;
            }
        }
    }

    public final int T0(int i) {
        int iH = this.q[0].h(i);
        for (int i2 = 1; i2 < this.p; i2++) {
            int iH2 = this.q[i2].h(i);
            if (iH2 > iH) {
                iH = iH2;
            }
        }
        return iH;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void U() {
        this.B.d();
        for (int i = 0; i < this.p; i++) {
            this.q[i].b();
        }
    }

    public final int U0(int i) {
        int iJ = this.q[0].j(i);
        for (int i2 = 1; i2 < this.p; i2++) {
            int iJ2 = this.q[i2].j(i);
            if (iJ2 < iJ) {
                iJ = iJ2;
            }
        }
        return iJ;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x007a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void V0(int r10, int r11, int r12) {
        /*
            Method dump skipped, instructions count: 223
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.V0(int, int, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void W(RecyclerView recyclerView) {
        RecyclerView recyclerView2 = this.b;
        if (recyclerView2 != null) {
            recyclerView2.removeCallbacks(this.K);
        }
        for (int i = 0; i < this.p; i++) {
            this.q[i].b();
        }
        recyclerView.requestLayout();
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00fd  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0102 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x002c A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View W0() {
        /*
            Method dump skipped, instructions count: 261
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.W0():android.view.View");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0053  */
    @Override // androidx.recyclerview.widget.AbstractC1381n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View X(android.view.View r9, int r10, androidx.recyclerview.widget.v0 r11, androidx.recyclerview.widget.B0 r12) {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.X(android.view.View, int, androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0):android.view.View");
    }

    public final boolean X0() {
        return this.b.getLayoutDirection() == 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void Y(AccessibilityEvent accessibilityEvent) {
        super.Y(accessibilityEvent);
        if (v() > 0) {
            View viewO0 = O0(false);
            View viewN0 = N0(false);
            if (viewO0 == null || viewN0 == null) {
                return;
            }
            int iK = AbstractC1381n0.K(viewO0);
            int iK2 = AbstractC1381n0.K(viewN0);
            if (iK < iK2) {
                accessibilityEvent.setFromIndex(iK);
                accessibilityEvent.setToIndex(iK2);
            } else {
                accessibilityEvent.setFromIndex(iK2);
                accessibilityEvent.setToIndex(iK);
            }
        }
    }

    public final void Y0(View view, int i, int i2) {
        RecyclerView recyclerView = this.b;
        Rect rect = this.G;
        if (recyclerView == null) {
            rect.set(0, 0, 0, 0);
        } else {
            rect.set(recyclerView.Q(view));
        }
        L0 l0 = (L0) view.getLayoutParams();
        int iK1 = k1(i, ((ViewGroup.MarginLayoutParams) l0).leftMargin + rect.left, ((ViewGroup.MarginLayoutParams) l0).rightMargin + rect.right);
        int iK12 = k1(i2, ((ViewGroup.MarginLayoutParams) l0).topMargin + rect.top, ((ViewGroup.MarginLayoutParams) l0).bottomMargin + rect.bottom);
        if (C0(view, iK1, iK12, l0)) {
            view.measure(iK1, iK12);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void Z(v0 v0Var, B0 b0, androidx.core.view.accessibility.e eVar) {
        super.Z(v0Var, b0, eVar);
        eVar.i("androidx.recyclerview.widget.StaggeredGridLayoutManager");
    }

    /* JADX WARN: Removed duplicated region for block: B:108:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01e1  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x0419  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Z0(androidx.recyclerview.widget.v0 r17, androidx.recyclerview.widget.B0 r18, boolean r19) {
        /*
            Method dump skipped, instructions count: 1076
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.Z0(androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0, boolean):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x000c  */
    @Override // androidx.recyclerview.widget.A0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.PointF a(int r4) {
        /*
            r3 = this;
            int r0 = r3.v()
            r1 = -1
            r2 = 1
            if (r0 != 0) goto Le
            boolean r4 = r3.x
            if (r4 == 0) goto L1b
        Lc:
            r1 = r2
            goto L1b
        Le:
            int r0 = r3.R0()
            if (r4 >= r0) goto L16
            r4 = r2
            goto L17
        L16:
            r4 = 0
        L17:
            boolean r0 = r3.x
            if (r4 == r0) goto Lc
        L1b:
            android.graphics.PointF r4 = new android.graphics.PointF
            r4.<init>()
            if (r1 != 0) goto L24
            r4 = 0
            return r4
        L24:
            int r0 = r3.t
            r2 = 0
            if (r0 != 0) goto L2f
            float r0 = (float) r1
            r4.x = r0
            r4.y = r2
            return r4
        L2f:
            r4.x = r2
            float r0 = (float) r1
            r4.y = r0
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.StaggeredGridLayoutManager.a(int):android.graphics.PointF");
    }

    public final boolean a1(int i) {
        if (this.t == 0) {
            return (i == -1) != this.x;
        }
        return ((i == -1) == this.x) == X0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void b0(v0 v0Var, B0 b0, View view, androidx.core.view.accessibility.e eVar) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (!(layoutParams instanceof L0)) {
            a0(view, eVar);
            return;
        }
        L0 l0 = (L0) layoutParams;
        if (this.t == 0) {
            C0220s c0220s = l0.e;
            eVar.k(androidx.webkit.internal.p.r(c0220s == null ? -1 : c0220s.e, 1, -1, -1, false));
        } else {
            C0220s c0220s2 = l0.e;
            eVar.k(androidx.webkit.internal.p.r(-1, -1, c0220s2 == null ? -1 : c0220s2.e, 1, false));
        }
    }

    public final void b1(int i, B0 b0) {
        int iR0;
        int i2;
        if (i > 0) {
            iR0 = S0();
            i2 = 1;
        } else {
            iR0 = R0();
            i2 = -1;
        }
        M m = this.v;
        m.a = true;
        i1(iR0, b0);
        h1(i2);
        m.c = iR0 + m.d;
        m.b = Math.abs(i);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void c(String str) {
        if (this.F == null) {
            super.c(str);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void c0(int i, int i2) {
        V0(i, i2, 1);
    }

    public final void c1(v0 v0Var, M m) {
        if (!m.a || m.i) {
            return;
        }
        if (m.b == 0) {
            if (m.e == -1) {
                d1(v0Var, m.g);
                return;
            } else {
                e1(v0Var, m.f);
                return;
            }
        }
        int i = 1;
        if (m.e == -1) {
            int i2 = m.f;
            int iJ = this.q[0].j(i2);
            while (i < this.p) {
                int iJ2 = this.q[i].j(i2);
                if (iJ2 > iJ) {
                    iJ = iJ2;
                }
                i++;
            }
            int i3 = i2 - iJ;
            d1(v0Var, i3 < 0 ? m.g : m.g - Math.min(i3, m.b));
            return;
        }
        int i4 = m.g;
        int iH = this.q[0].h(i4);
        while (i < this.p) {
            int iH2 = this.q[i].h(i4);
            if (iH2 < iH) {
                iH = iH2;
            }
            i++;
        }
        int i5 = iH - m.g;
        e1(v0Var, i5 < 0 ? m.f : Math.min(i5, m.b) + m.f);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean d() {
        return this.t == 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void d0() {
        this.B.d();
        t0();
    }

    public final void d1(v0 v0Var, int i) {
        for (int iV = v() - 1; iV >= 0; iV--) {
            View viewU = u(iV);
            if (this.r.e(viewU) < i || this.r.n(viewU) < i) {
                return;
            }
            L0 l0 = (L0) viewU.getLayoutParams();
            l0.getClass();
            if (((ArrayList) l0.e.f).size() == 1) {
                return;
            }
            C0220s c0220s = l0.e;
            ArrayList arrayList = (ArrayList) c0220s.f;
            int size = arrayList.size();
            View view = (View) arrayList.remove(size - 1);
            L0 l02 = (L0) view.getLayoutParams();
            l02.e = null;
            if (l02.a.isRemoved() || l02.a.isUpdated()) {
                c0220s.d -= ((StaggeredGridLayoutManager) c0220s.g).r.c(view);
            }
            if (size == 1) {
                c0220s.b = Integer.MIN_VALUE;
            }
            c0220s.c = Integer.MIN_VALUE;
            q0(viewU, v0Var);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean e() {
        return this.t == 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void e0(int i, int i2) {
        V0(i, i2, 8);
    }

    public final void e1(v0 v0Var, int i) {
        while (v() > 0) {
            View viewU = u(0);
            if (this.r.b(viewU) > i || this.r.m(viewU) > i) {
                return;
            }
            L0 l0 = (L0) viewU.getLayoutParams();
            l0.getClass();
            if (((ArrayList) l0.e.f).size() == 1) {
                return;
            }
            C0220s c0220s = l0.e;
            ArrayList arrayList = (ArrayList) c0220s.f;
            View view = (View) arrayList.remove(0);
            L0 l02 = (L0) view.getLayoutParams();
            l02.e = null;
            if (arrayList.size() == 0) {
                c0220s.c = Integer.MIN_VALUE;
            }
            if (l02.a.isRemoved() || l02.a.isUpdated()) {
                c0220s.d -= ((StaggeredGridLayoutManager) c0220s.g).r.c(view);
            }
            c0220s.b = Integer.MIN_VALUE;
            q0(viewU, v0Var);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean f(C1383o0 c1383o0) {
        return c1383o0 instanceof L0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void f0(int i, int i2) {
        V0(i, i2, 2);
    }

    public final void f1() {
        if (this.t == 1 || !X0()) {
            this.x = this.w;
        } else {
            this.x = !this.w;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void g0(int i, int i2) {
        V0(i, i2, 4);
    }

    public final int g1(int i, v0 v0Var, B0 b0) {
        if (v() == 0 || i == 0) {
            return 0;
        }
        b1(i, b0);
        M m = this.v;
        int iM0 = M0(v0Var, m, b0);
        if (m.b >= iM0) {
            i = i < 0 ? -iM0 : iM0;
        }
        this.r.o(-i);
        this.D = this.x;
        m.b = 0;
        c1(v0Var, m);
        return i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void h(int i, int i2, B0 b0, C0210h c0210h) {
        M m;
        int iH;
        int iJ;
        if (this.t != 0) {
            i = i2;
        }
        if (v() == 0 || i == 0) {
            return;
        }
        b1(i, b0);
        int[] iArr = this.J;
        if (iArr == null || iArr.length < this.p) {
            this.J = new int[this.p];
        }
        int i3 = 0;
        int i4 = 0;
        while (true) {
            int i5 = this.p;
            m = this.v;
            if (i3 >= i5) {
                break;
            }
            if (m.d == -1) {
                iH = m.f;
                iJ = this.q[i3].j(iH);
            } else {
                iH = this.q[i3].h(m.g);
                iJ = m.g;
            }
            int i6 = iH - iJ;
            if (i6 >= 0) {
                this.J[i4] = i6;
                i4++;
            }
            i3++;
        }
        Arrays.sort(this.J, 0, i4);
        for (int i7 = 0; i7 < i4; i7++) {
            int i8 = m.c;
            if (i8 < 0 || i8 >= b0.b()) {
                return;
            }
            c0210h.b(m.c, this.J[i7]);
            m.c += m.d;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void h0(v0 v0Var, B0 b0) {
        Z0(v0Var, b0, true);
    }

    public final void h1(int i) {
        M m = this.v;
        m.e = i;
        m.d = this.x != (i == -1) ? -1 : 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void i0(B0 b0) {
        this.z = -1;
        this.A = Integer.MIN_VALUE;
        this.F = null;
        this.H.a();
    }

    public final void i1(int i, B0 b0) {
        int iL;
        int iL2;
        int i2;
        M m = this.v;
        boolean z = false;
        m.b = 0;
        m.c = i;
        S s = this.e;
        if (!(s != null && s.e) || (i2 = b0.a) == -1) {
            iL = 0;
            iL2 = 0;
        } else {
            if (this.x == (i2 < i)) {
                iL = this.r.l();
                iL2 = 0;
            } else {
                iL2 = this.r.l();
                iL = 0;
            }
        }
        RecyclerView recyclerView = this.b;
        if (recyclerView == null || !recyclerView.h) {
            m.g = this.r.f() + iL;
            m.f = -iL2;
        } else {
            m.f = this.r.k() - iL2;
            m.g = this.r.g() + iL;
        }
        m.h = false;
        m.a = true;
        if (this.r.i() == 0 && this.r.f() == 0) {
            z = true;
        }
        m.i = z;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int j(B0 b0) {
        return J0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void j0(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            SavedState savedState = (SavedState) parcelable;
            this.F = savedState;
            if (this.z != -1) {
                savedState.d = null;
                savedState.c = 0;
                savedState.a = -1;
                savedState.b = -1;
                savedState.d = null;
                savedState.c = 0;
                savedState.e = 0;
                savedState.f = null;
                savedState.g = null;
            }
            t0();
        }
    }

    public final void j1(C0220s c0220s, int i, int i2) {
        int i3 = c0220s.d;
        int i4 = c0220s.e;
        if (i != -1) {
            int i5 = c0220s.c;
            if (i5 == Integer.MIN_VALUE) {
                c0220s.a();
                i5 = c0220s.c;
            }
            if (i5 - i3 >= i2) {
                this.y.set(i4, false);
                return;
            }
            return;
        }
        int i6 = c0220s.b;
        if (i6 == Integer.MIN_VALUE) {
            View view = (View) ((ArrayList) c0220s.f).get(0);
            L0 l0 = (L0) view.getLayoutParams();
            c0220s.b = ((StaggeredGridLayoutManager) c0220s.g).r.e(view);
            l0.getClass();
            i6 = c0220s.b;
        }
        if (i6 + i3 <= i2) {
            this.y.set(i4, false);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int k(B0 b0) {
        return K0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final Parcelable k0() {
        int iJ;
        int iK;
        int[] iArr;
        SavedState savedState = this.F;
        if (savedState != null) {
            SavedState savedState2 = new SavedState();
            savedState2.c = savedState.c;
            savedState2.a = savedState.a;
            savedState2.b = savedState.b;
            savedState2.d = savedState.d;
            savedState2.e = savedState.e;
            savedState2.f = savedState.f;
            savedState2.h = savedState.h;
            savedState2.i = savedState.i;
            savedState2.j = savedState.j;
            savedState2.g = savedState.g;
            return savedState2;
        }
        SavedState savedState3 = new SavedState();
        savedState3.h = this.w;
        savedState3.i = this.D;
        savedState3.j = this.E;
        N0 n0 = this.B;
        if (n0 == null || (iArr = (int[]) n0.a) == null) {
            savedState3.e = 0;
        } else {
            savedState3.f = iArr;
            savedState3.e = iArr.length;
            savedState3.g = (ArrayList) n0.b;
        }
        if (v() <= 0) {
            savedState3.a = -1;
            savedState3.b = -1;
            savedState3.c = 0;
            return savedState3;
        }
        savedState3.a = this.D ? S0() : R0();
        View viewN0 = this.x ? N0(true) : O0(true);
        savedState3.b = viewN0 != null ? AbstractC1381n0.K(viewN0) : -1;
        int i = this.p;
        savedState3.c = i;
        savedState3.d = new int[i];
        for (int i2 = 0; i2 < this.p; i2++) {
            if (this.D) {
                iJ = this.q[i2].h(Integer.MIN_VALUE);
                if (iJ != Integer.MIN_VALUE) {
                    iK = this.r.g();
                    iJ -= iK;
                }
            } else {
                iJ = this.q[i2].j(Integer.MIN_VALUE);
                if (iJ != Integer.MIN_VALUE) {
                    iK = this.r.k();
                    iJ -= iK;
                }
            }
            savedState3.d[i2] = iJ;
        }
        return savedState3;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int l(B0 b0) {
        return L0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void l0(int i) {
        if (i == 0) {
            I0();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int m(B0 b0) {
        return J0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int n(B0 b0) {
        return K0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int o(B0 b0) {
        return L0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 r() {
        return this.t == 0 ? new L0(-2, -1) : new L0(-1, -2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 s(Context context, AttributeSet attributeSet) {
        return new L0(context, attributeSet);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final C1383o0 t(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof ViewGroup.MarginLayoutParams ? new L0((ViewGroup.MarginLayoutParams) layoutParams) : new L0(layoutParams);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int u0(int i, v0 v0Var, B0 b0) {
        return g1(i, v0Var, b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void v0(int i) {
        SavedState savedState = this.F;
        if (savedState != null && savedState.a != i) {
            savedState.d = null;
            savedState.c = 0;
            savedState.a = -1;
            savedState.b = -1;
        }
        this.z = i;
        this.A = Integer.MIN_VALUE;
        t0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int w0(int i, v0 v0Var, B0 b0) {
        return g1(i, v0Var, b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int x(v0 v0Var, B0 b0) {
        if (this.t == 1) {
            return Math.min(this.p, b0.b());
        }
        return -1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void z0(Rect rect, int i, int i2) {
        int iG;
        int iG2;
        int i3 = this.p;
        int I = I() + H();
        int iG3 = G() + J();
        if (this.t == 1) {
            int iHeight = rect.height() + iG3;
            RecyclerView recyclerView = this.b;
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            iG2 = AbstractC1381n0.g(i2, iHeight, recyclerView.getMinimumHeight());
            iG = AbstractC1381n0.g(i, (this.u * i3) + I, this.b.getMinimumWidth());
        } else {
            int iWidth = rect.width() + I;
            RecyclerView recyclerView2 = this.b;
            WeakHashMap weakHashMap2 = androidx.core.view.V.a;
            iG = AbstractC1381n0.g(i, iWidth, recyclerView2.getMinimumWidth());
            iG2 = AbstractC1381n0.g(i2, (this.u * i3) + iG3, this.b.getMinimumHeight());
        }
        this.b.setMeasuredDimension(iG, iG2);
    }
}
