package androidx.recyclerview.widget;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.PointF;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.collection.C0210h;
import com.amazon.device.ads.DtbConstants;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public class LinearLayoutManager extends AbstractC1381n0 implements K, A0 {
    public final N A;
    public final O B;
    public int C;
    public final int[] D;
    public int p;
    public P q;
    public androidx.emoji2.text.g r;
    public boolean s;
    public final boolean t;
    public boolean u;
    public boolean v;
    public final boolean w;
    public int x;
    public int y;
    public SavedState z;

    @SuppressLint({"BanParcelableUsage"})
    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new Q();
        public int a;
        public int b;
        public boolean c;

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            parcel.writeInt(this.a);
            parcel.writeInt(this.b);
            parcel.writeInt(this.c ? 1 : 0);
        }
    }

    public LinearLayoutManager(@SuppressLint({"UnknownNullness"}) Context context) {
        this(1);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean D0() {
        if (this.m != 1073741824 && this.l != 1073741824) {
            int iV = v();
            for (int i = 0; i < iV; i++) {
                ViewGroup.LayoutParams layoutParams = u(i).getLayoutParams();
                if (layoutParams.width < 0 && layoutParams.height < 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public void F0(RecyclerView recyclerView, B0 b0, int i) {
        S s = new S(recyclerView.getContext());
        s.a = i;
        G0(s);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public boolean H0() {
        return this.z == null && this.s == this.v;
    }

    public void I0(B0 b0, int[] iArr) {
        int i;
        int iL = b0.a != -1 ? this.r.l() : 0;
        if (this.q.f == -1) {
            i = 0;
        } else {
            i = iL;
            iL = 0;
        }
        iArr[0] = iL;
        iArr[1] = i;
    }

    public void J0(B0 b0, P p, C0210h c0210h) {
        int i = p.d;
        if (i < 0 || i >= b0.b()) {
            return;
        }
        c0210h.b(i, Math.max(0, p.g));
    }

    public final int K0(B0 b0) {
        if (v() == 0) {
            return 0;
        }
        O0();
        androidx.emoji2.text.g gVar = this.r;
        boolean z = !this.w;
        return AbstractC1358c.d(b0, gVar, R0(z), Q0(z), this, this.w);
    }

    public final int L0(B0 b0) {
        if (v() == 0) {
            return 0;
        }
        O0();
        androidx.emoji2.text.g gVar = this.r;
        boolean z = !this.w;
        return AbstractC1358c.e(b0, gVar, R0(z), Q0(z), this, this.w, this.u);
    }

    public final int M0(B0 b0) {
        if (v() == 0) {
            return 0;
        }
        O0();
        androidx.emoji2.text.g gVar = this.r;
        boolean z = !this.w;
        return AbstractC1358c.f(b0, gVar, R0(z), Q0(z), this, this.w);
    }

    public final int N0(int i) {
        return i != 1 ? i != 2 ? i != 17 ? i != 33 ? i != 66 ? (i == 130 && this.p == 1) ? 1 : Integer.MIN_VALUE : this.p == 0 ? 1 : Integer.MIN_VALUE : this.p == 1 ? -1 : Integer.MIN_VALUE : this.p == 0 ? -1 : Integer.MIN_VALUE : (this.p != 1 && c1()) ? -1 : 1 : (this.p != 1 && c1()) ? 1 : -1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean O() {
        return true;
    }

    public final void O0() {
        if (this.q == null) {
            P p = new P();
            p.a = true;
            p.h = 0;
            p.i = 0;
            p.k = null;
            this.q = p;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final boolean P() {
        return this.t;
    }

    public final int P0(v0 v0Var, P p, B0 b0, boolean z) {
        int i;
        int i2 = p.c;
        int i3 = p.g;
        if (i3 != Integer.MIN_VALUE) {
            if (i2 < 0) {
                p.g = i3 + i2;
            }
            f1(v0Var, p);
        }
        int i4 = p.c + p.h;
        while (true) {
            if ((!p.l && i4 <= 0) || (i = p.d) < 0 || i >= b0.b()) {
                break;
            }
            O o = this.B;
            o.a = 0;
            o.b = false;
            o.c = false;
            o.d = false;
            d1(v0Var, b0, p, o);
            if (!o.b) {
                int i5 = p.b;
                int i6 = o.a;
                p.b = (p.f * i6) + i5;
                if (!o.c || p.k != null || !b0.g) {
                    p.c -= i6;
                    i4 -= i6;
                }
                int i7 = p.g;
                if (i7 != Integer.MIN_VALUE) {
                    int i8 = i7 + i6;
                    p.g = i8;
                    int i9 = p.c;
                    if (i9 < 0) {
                        p.g = i8 + i9;
                    }
                    f1(v0Var, p);
                }
                if (z && o.d) {
                    break;
                }
            } else {
                break;
            }
        }
        return i2 - p.c;
    }

    public final View Q0(boolean z) {
        return this.u ? W0(0, v(), z, true) : W0(v() - 1, -1, z, true);
    }

    public final View R0(boolean z) {
        return this.u ? W0(v() - 1, -1, z, true) : W0(0, v(), z, true);
    }

    public final int S0() {
        View viewW0 = W0(0, v(), false, true);
        if (viewW0 == null) {
            return -1;
        }
        return AbstractC1381n0.K(viewW0);
    }

    public final int T0() {
        View viewW0 = W0(v() - 1, -1, true, false);
        if (viewW0 == null) {
            return -1;
        }
        return AbstractC1381n0.K(viewW0);
    }

    public final int U0() {
        View viewW0 = W0(v() - 1, -1, false, true);
        if (viewW0 == null) {
            return -1;
        }
        return AbstractC1381n0.K(viewW0);
    }

    public final View V0(int i, int i2) {
        int i3;
        int i4;
        O0();
        if (i2 <= i && i2 >= i) {
            return u(i);
        }
        if (this.r.e(u(i)) < this.r.k()) {
            i3 = 16644;
            i4 = 16388;
        } else {
            i3 = 4161;
            i4 = 4097;
        }
        return this.p == 0 ? this.c.f(i, i2, i3, i4) : this.d.f(i, i2, i3, i4);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void W(RecyclerView recyclerView) {
    }

    public final View W0(int i, int i2, boolean z, boolean z2) {
        O0();
        int i3 = DtbConstants.DEFAULT_PLAYER_WIDTH;
        int i4 = z ? 24579 : 320;
        if (!z2) {
            i3 = 0;
        }
        return this.p == 0 ? this.c.f(i, i2, i4, i3) : this.d.f(i, i2, i4, i3);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public View X(View view, int i, v0 v0Var, B0 b0) {
        int iN0;
        h1();
        if (v() != 0 && (iN0 = N0(i)) != Integer.MIN_VALUE) {
            O0();
            m1(iN0, (int) (this.r.l() * 0.33333334f), false, b0);
            P p = this.q;
            p.g = Integer.MIN_VALUE;
            p.a = false;
            P0(v0Var, p, b0, true);
            View viewV0 = iN0 == -1 ? this.u ? V0(v() - 1, -1) : V0(0, v()) : this.u ? V0(0, v()) : V0(v() - 1, -1);
            View viewB1 = iN0 == -1 ? b1() : a1();
            if (!viewB1.hasFocusable()) {
                return viewV0;
            }
            if (viewV0 != null) {
                return viewB1;
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0079  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.view.View X0(androidx.recyclerview.widget.v0 r17, androidx.recyclerview.widget.B0 r18, boolean r19, boolean r20) {
        /*
            r16 = this;
            r0 = r16
            r0.O0()
            int r1 = r0.v()
            r2 = 0
            r3 = 1
            if (r20 == 0) goto L15
            int r1 = r0.v()
            int r1 = r1 - r3
            r4 = -1
            r5 = r4
            goto L18
        L15:
            r4 = r1
            r1 = r2
            r5 = r3
        L18:
            int r6 = r18.b()
            androidx.emoji2.text.g r7 = r0.r
            int r7 = r7.k()
            androidx.emoji2.text.g r8 = r0.r
            int r8 = r8.g()
            r9 = 0
            r10 = r9
            r11 = r10
        L2b:
            if (r1 == r4) goto L7c
            android.view.View r12 = r0.u(r1)
            int r13 = androidx.recyclerview.widget.AbstractC1381n0.K(r12)
            androidx.emoji2.text.g r14 = r0.r
            int r14 = r14.e(r12)
            androidx.emoji2.text.g r15 = r0.r
            int r15 = r15.b(r12)
            if (r13 < 0) goto L7a
            if (r13 >= r6) goto L7a
            android.view.ViewGroup$LayoutParams r13 = r12.getLayoutParams()
            androidx.recyclerview.widget.o0 r13 = (androidx.recyclerview.widget.C1383o0) r13
            androidx.recyclerview.widget.F0 r13 = r13.a
            boolean r13 = r13.isRemoved()
            if (r13 == 0) goto L57
            if (r11 != 0) goto L7a
            r11 = r12
            goto L7a
        L57:
            if (r15 > r7) goto L5d
            if (r14 >= r7) goto L5d
            r13 = r3
            goto L5e
        L5d:
            r13 = r2
        L5e:
            if (r14 < r8) goto L64
            if (r15 <= r8) goto L64
            r14 = r3
            goto L65
        L64:
            r14 = r2
        L65:
            if (r13 != 0) goto L6b
            if (r14 == 0) goto L6a
            goto L6b
        L6a:
            return r12
        L6b:
            if (r19 == 0) goto L73
            if (r14 == 0) goto L70
            goto L75
        L70:
            if (r9 != 0) goto L7a
            goto L79
        L73:
            if (r13 == 0) goto L77
        L75:
            r10 = r12
            goto L7a
        L77:
            if (r9 != 0) goto L7a
        L79:
            r9 = r12
        L7a:
            int r1 = r1 + r5
            goto L2b
        L7c:
            if (r9 == 0) goto L7f
            return r9
        L7f:
            if (r10 == 0) goto L82
            return r10
        L82:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.LinearLayoutManager.X0(androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0, boolean, boolean):android.view.View");
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void Y(AccessibilityEvent accessibilityEvent) {
        super.Y(accessibilityEvent);
        if (v() > 0) {
            accessibilityEvent.setFromIndex(S0());
            accessibilityEvent.setToIndex(U0());
        }
    }

    public final int Y0(int i, v0 v0Var, B0 b0, boolean z) {
        int iG;
        int iG2 = this.r.g() - i;
        if (iG2 <= 0) {
            return 0;
        }
        int i2 = -i1(-iG2, v0Var, b0);
        int i3 = i + i2;
        if (!z || (iG = this.r.g() - i3) <= 0) {
            return i2;
        }
        this.r.o(iG);
        return iG + i2;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public void Z(v0 v0Var, B0 b0, androidx.core.view.accessibility.e eVar) {
        super.Z(v0Var, b0, eVar);
        AbstractC1361d0 abstractC1361d0 = this.b.m;
        if (abstractC1361d0 == null || abstractC1361d0.getItemCount() <= 0) {
            return;
        }
        eVar.b(androidx.core.view.accessibility.d.m);
    }

    public final int Z0(int i, v0 v0Var, B0 b0, boolean z) {
        int iK;
        int iK2 = i - this.r.k();
        if (iK2 <= 0) {
            return 0;
        }
        int i2 = -i1(iK2, v0Var, b0);
        int i3 = i + i2;
        if (!z || (iK = i3 - this.r.k()) <= 0) {
            return i2;
        }
        this.r.o(-iK);
        return i2 - iK;
    }

    @Override // androidx.recyclerview.widget.A0
    public final PointF a(int i) {
        if (v() == 0) {
            return null;
        }
        int i2 = (i < AbstractC1381n0.K(u(0))) != this.u ? -1 : 1;
        return this.p == 0 ? new PointF(i2, DefinitionKt.NO_Float_VALUE) : new PointF(DefinitionKt.NO_Float_VALUE, i2);
    }

    public final View a1() {
        return u(this.u ? 0 : v() - 1);
    }

    public final View b1() {
        return u(this.u ? v() - 1 : 0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void c(String str) {
        if (this.z == null) {
            super.c(str);
        }
    }

    public final boolean c1() {
        return this.b.getLayoutDirection() == 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public boolean d() {
        return this.p == 0;
    }

    public void d1(v0 v0Var, B0 b0, P p, O o) {
        int iH;
        int i;
        int i2;
        int iD;
        View viewB = p.b(v0Var);
        if (viewB == null) {
            o.b = true;
            return;
        }
        C1383o0 c1383o0 = (C1383o0) viewB.getLayoutParams();
        if (p.k == null) {
            if (this.u == (p.f == -1)) {
                b(viewB, -1, false);
            } else {
                b(viewB, 0, false);
            }
        } else {
            if (this.u == (p.f == -1)) {
                b(viewB, -1, true);
            } else {
                b(viewB, 0, true);
            }
        }
        C1383o0 c1383o02 = (C1383o0) viewB.getLayoutParams();
        Rect rectQ = this.b.Q(viewB);
        int i3 = rectQ.left + rectQ.right;
        int i4 = rectQ.top + rectQ.bottom;
        int iW = AbstractC1381n0.w(this.n, this.l, I() + H() + ((ViewGroup.MarginLayoutParams) c1383o02).leftMargin + ((ViewGroup.MarginLayoutParams) c1383o02).rightMargin + i3, ((ViewGroup.MarginLayoutParams) c1383o02).width, d());
        int iW2 = AbstractC1381n0.w(this.o, this.m, G() + J() + ((ViewGroup.MarginLayoutParams) c1383o02).topMargin + ((ViewGroup.MarginLayoutParams) c1383o02).bottomMargin + i4, ((ViewGroup.MarginLayoutParams) c1383o02).height, e());
        if (C0(viewB, iW, iW2, c1383o02)) {
            viewB.measure(iW, iW2);
        }
        o.a = this.r.c(viewB);
        if (this.p == 1) {
            if (c1()) {
                iD = this.n - I();
                iH = iD - this.r.d(viewB);
            } else {
                iH = H();
                iD = this.r.d(viewB) + iH;
            }
            if (p.f == -1) {
                i = p.b;
                i2 = i - o.a;
            } else {
                i2 = p.b;
                i = o.a + i2;
            }
        } else {
            int iJ = J();
            int iD2 = this.r.d(viewB) + iJ;
            if (p.f == -1) {
                int i5 = p.b;
                int i6 = i5 - o.a;
                iD = i5;
                i = iD2;
                iH = i6;
                i2 = iJ;
            } else {
                int i7 = p.b;
                int i8 = o.a + i7;
                iH = i7;
                i = iD2;
                i2 = iJ;
                iD = i8;
            }
        }
        AbstractC1381n0.R(viewB, iH, i2, iD, i);
        if (c1383o0.a.isRemoved() || c1383o0.a.isUpdated()) {
            o.c = true;
        }
        o.d = viewB.hasFocusable();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public boolean e() {
        return this.p == 1;
    }

    public void e1(v0 v0Var, B0 b0, N n, int i) {
    }

    public final void f1(v0 v0Var, P p) {
        if (!p.a || p.l) {
            return;
        }
        int i = p.g;
        int i2 = p.i;
        if (p.f == -1) {
            int iV = v();
            if (i < 0) {
                return;
            }
            int iF = (this.r.f() - i) + i2;
            if (this.u) {
                for (int i3 = 0; i3 < iV; i3++) {
                    View viewU = u(i3);
                    if (this.r.e(viewU) < iF || this.r.n(viewU) < iF) {
                        g1(v0Var, 0, i3);
                        return;
                    }
                }
                return;
            }
            int i4 = iV - 1;
            for (int i5 = i4; i5 >= 0; i5--) {
                View viewU2 = u(i5);
                if (this.r.e(viewU2) < iF || this.r.n(viewU2) < iF) {
                    g1(v0Var, i4, i5);
                    return;
                }
            }
            return;
        }
        if (i < 0) {
            return;
        }
        int i6 = i - i2;
        int iV2 = v();
        if (!this.u) {
            for (int i7 = 0; i7 < iV2; i7++) {
                View viewU3 = u(i7);
                if (this.r.b(viewU3) > i6 || this.r.m(viewU3) > i6) {
                    g1(v0Var, 0, i7);
                    return;
                }
            }
            return;
        }
        int i8 = iV2 - 1;
        for (int i9 = i8; i9 >= 0; i9--) {
            View viewU4 = u(i9);
            if (this.r.b(viewU4) > i6 || this.r.m(viewU4) > i6) {
                g1(v0Var, i8, i9);
                return;
            }
        }
    }

    public final void g1(v0 v0Var, int i, int i2) {
        if (i == i2) {
            return;
        }
        if (i2 <= i) {
            while (i > i2) {
                View viewU = u(i);
                r0(i);
                v0Var.h(viewU);
                i--;
            }
            return;
        }
        for (int i3 = i2 - 1; i3 >= i; i3--) {
            View viewU2 = u(i3);
            r0(i3);
            v0Var.h(viewU2);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void h(int i, int i2, B0 b0, C0210h c0210h) {
        if (this.p != 0) {
            i = i2;
        }
        if (v() == 0 || i == 0) {
            return;
        }
        O0();
        m1(i > 0 ? 1 : -1, Math.abs(i), true, b0);
        J0(b0, this.q, c0210h);
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x01d9  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x022b  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0194  */
    @Override // androidx.recyclerview.widget.AbstractC1381n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void h0(androidx.recyclerview.widget.v0 r18, androidx.recyclerview.widget.B0 r19) {
        /*
            Method dump skipped, instructions count: 1087
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.LinearLayoutManager.h0(androidx.recyclerview.widget.v0, androidx.recyclerview.widget.B0):void");
    }

    public final void h1() {
        if (this.p == 1 || !c1()) {
            this.u = this.t;
        } else {
            this.u = !this.t;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void i(int i, C0210h c0210h) {
        boolean z;
        int i2;
        SavedState savedState = this.z;
        if (savedState == null || (i2 = savedState.a) < 0) {
            h1();
            z = this.u;
            i2 = this.x;
            if (i2 == -1) {
                i2 = z ? i - 1 : 0;
            }
        } else {
            z = savedState.c;
        }
        int i3 = z ? -1 : 1;
        for (int i4 = 0; i4 < this.C && i2 >= 0 && i2 < i; i4++) {
            c0210h.b(i2, 0);
            i2 += i3;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public void i0(B0 b0) {
        this.z = null;
        this.x = -1;
        this.y = Integer.MIN_VALUE;
        this.A.d();
    }

    public final int i1(int i, v0 v0Var, B0 b0) {
        if (v() != 0 && i != 0) {
            O0();
            this.q.a = true;
            int i2 = i > 0 ? 1 : -1;
            int iAbs = Math.abs(i);
            m1(i2, iAbs, true, b0);
            P p = this.q;
            int iP0 = P0(v0Var, p, b0, false) + p.g;
            if (iP0 >= 0) {
                if (iAbs > iP0) {
                    i = i2 * iP0;
                }
                this.r.o(-i);
                this.q.j = i;
                return i;
            }
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int j(B0 b0) {
        return K0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void j0(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            SavedState savedState = (SavedState) parcelable;
            this.z = savedState;
            if (this.x != -1) {
                savedState.a = -1;
            }
            t0();
        }
    }

    public final void j1(int i, int i2) {
        this.x = i;
        this.y = i2;
        SavedState savedState = this.z;
        if (savedState != null) {
            savedState.a = -1;
        }
        t0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public int k(B0 b0) {
        return L0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final Parcelable k0() {
        SavedState savedState = this.z;
        if (savedState != null) {
            SavedState savedState2 = new SavedState();
            savedState2.a = savedState.a;
            savedState2.b = savedState.b;
            savedState2.c = savedState.c;
            return savedState2;
        }
        SavedState savedState3 = new SavedState();
        if (v() <= 0) {
            savedState3.a = -1;
            return savedState3;
        }
        O0();
        boolean z = this.s ^ this.u;
        savedState3.c = z;
        if (z) {
            View viewA1 = a1();
            savedState3.b = this.r.g() - this.r.b(viewA1);
            savedState3.a = AbstractC1381n0.K(viewA1);
            return savedState3;
        }
        View viewB1 = b1();
        savedState3.a = AbstractC1381n0.K(viewB1);
        savedState3.b = this.r.e(viewB1) - this.r.k();
        return savedState3;
    }

    public final void k1(int i) {
        if (i != 0 && i != 1) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "invalid orientation:"));
        }
        c(null);
        if (i != this.p || this.r == null) {
            androidx.emoji2.text.g gVarA = androidx.emoji2.text.g.a(this, i);
            this.r = gVarA;
            this.A.f = gVarA;
            this.p = i;
            t0();
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public int l(B0 b0) {
        return M0(b0);
    }

    public void l1(boolean z) {
        c(null);
        if (this.v == z) {
            return;
        }
        this.v = z;
        t0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final int m(B0 b0) {
        return K0(b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public boolean m0(int i, Bundle bundle) {
        int iMin;
        if (super.m0(i, bundle)) {
            return true;
        }
        if (i == 16908343 && bundle != null) {
            if (this.p == 1) {
                int i2 = bundle.getInt("android.view.accessibility.action.ARGUMENT_ROW_INT", -1);
                if (i2 < 0) {
                    return false;
                }
                RecyclerView recyclerView = this.b;
                iMin = Math.min(i2, M(recyclerView.c, recyclerView.r1) - 1);
            } else {
                int i3 = bundle.getInt("android.view.accessibility.action.ARGUMENT_COLUMN_INT", -1);
                if (i3 < 0) {
                    return false;
                }
                RecyclerView recyclerView2 = this.b;
                iMin = Math.min(i3, x(recyclerView2.c, recyclerView2.r1) - 1);
            }
            if (iMin >= 0) {
                j1(iMin, 0);
                return true;
            }
        }
        return false;
    }

    public final void m1(int i, int i2, boolean z, B0 b0) {
        int iK;
        this.q.l = this.r.i() == 0 && this.r.f() == 0;
        this.q.f = i;
        int[] iArr = this.D;
        iArr[0] = 0;
        iArr[1] = 0;
        I0(b0, iArr);
        int iMax = Math.max(0, iArr[0]);
        int iMax2 = Math.max(0, iArr[1]);
        boolean z2 = i == 1;
        P p = this.q;
        int i3 = z2 ? iMax2 : iMax;
        p.h = i3;
        if (!z2) {
            iMax = iMax2;
        }
        p.i = iMax;
        if (z2) {
            p.h = this.r.h() + i3;
            View viewA1 = a1();
            P p2 = this.q;
            p2.e = this.u ? -1 : 1;
            int iK2 = AbstractC1381n0.K(viewA1);
            P p3 = this.q;
            p2.d = iK2 + p3.e;
            p3.b = this.r.b(viewA1);
            iK = this.r.b(viewA1) - this.r.g();
        } else {
            View viewB1 = b1();
            P p4 = this.q;
            p4.h = this.r.k() + p4.h;
            P p5 = this.q;
            p5.e = this.u ? 1 : -1;
            int iK3 = AbstractC1381n0.K(viewB1);
            P p6 = this.q;
            p5.d = iK3 + p6.e;
            p6.b = this.r.e(viewB1);
            iK = (-this.r.e(viewB1)) + this.r.k();
        }
        P p7 = this.q;
        p7.c = i2;
        if (z) {
            p7.c = i2 - iK;
        }
        p7.g = iK;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public int n(B0 b0) {
        return L0(b0);
    }

    public final void n1(int i, int i2) {
        this.q.c = this.r.g() - i2;
        P p = this.q;
        p.e = this.u ? -1 : 1;
        p.d = i;
        p.f = 1;
        p.b = i2;
        p.g = Integer.MIN_VALUE;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public int o(B0 b0) {
        return M0(b0);
    }

    public final void o1(int i, int i2) {
        this.q.c = i2 - this.r.k();
        P p = this.q;
        p.d = i;
        p.e = this.u ? 1 : -1;
        p.f = -1;
        p.b = i2;
        p.g = Integer.MIN_VALUE;
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final View q(int i) {
        int iV = v();
        if (iV == 0) {
            return null;
        }
        int iK = i - AbstractC1381n0.K(u(0));
        if (iK >= 0 && iK < iV) {
            View viewU = u(iK);
            if (AbstractC1381n0.K(viewU) == i) {
                return viewU;
            }
        }
        return super.q(i);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public C1383o0 r() {
        return new C1383o0(-2, -2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public int u0(int i, v0 v0Var, B0 b0) {
        if (this.p == 1) {
            return 0;
        }
        return i1(i, v0Var, b0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public final void v0(int i) {
        this.x = i;
        this.y = Integer.MIN_VALUE;
        SavedState savedState = this.z;
        if (savedState != null) {
            savedState.a = -1;
        }
        t0();
    }

    @Override // androidx.recyclerview.widget.AbstractC1381n0
    public int w0(int i, v0 v0Var, B0 b0) {
        if (this.p == 0) {
            return 0;
        }
        return i1(i, v0Var, b0);
    }

    public LinearLayoutManager(int i) {
        this.p = 1;
        this.t = false;
        this.u = false;
        this.v = false;
        this.w = true;
        this.x = -1;
        this.y = Integer.MIN_VALUE;
        this.z = null;
        this.A = new N();
        this.B = new O();
        this.C = 2;
        this.D = new int[2];
        k1(i);
        c(null);
        if (this.t) {
            this.t = false;
            t0();
        }
    }

    @SuppressLint({"UnknownNullness"})
    public LinearLayoutManager(Context context, AttributeSet attributeSet, int i, int i2) {
        this.p = 1;
        this.t = false;
        this.u = false;
        this.v = false;
        this.w = true;
        this.x = -1;
        this.y = Integer.MIN_VALUE;
        this.z = null;
        this.A = new N();
        this.B = new O();
        this.C = 2;
        this.D = new int[2];
        C1379m0 c1379m0L = AbstractC1381n0.L(context, attributeSet, i, i2);
        k1(c1379m0L.a);
        boolean z = c1379m0L.c;
        c(null);
        if (z != this.t) {
            this.t = z;
            t0();
        }
        l1(c1379m0L.d);
    }
}
