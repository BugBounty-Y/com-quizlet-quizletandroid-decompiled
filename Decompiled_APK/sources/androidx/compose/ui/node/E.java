package androidx.compose.ui.node;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.core.C0242g;
import androidx.compose.runtime.C0835x;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0802j;
import androidx.compose.runtime.InterfaceC0837y;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.platform.C0971v;
import androidx.compose.ui.platform.Y0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E implements InterfaceC0802j, h0, InterfaceC0915k {
    public static final A J = new A("Undefined intrinsics block and it is required");
    public static final C0929z K = new C0929z();
    public static final androidx.camera.camera2.internal.a0 L = new androidx.camera.camera2.internal.a0(3);
    public boolean A;
    public androidx.compose.ui.q B;
    public androidx.compose.ui.q C;
    public androidx.compose.ui.viewinterop.c D;
    public androidx.compose.ui.input.pointer.s E;
    public boolean F;
    public boolean G;
    public int H;
    public int I;
    public final boolean a;
    public int b;
    public E c;
    public int d;
    public final androidx.work.impl.model.c e;
    public androidx.compose.runtime.collection.b f;
    public boolean g;
    public E h;
    public C0971v i;
    public androidx.compose.ui.viewinterop.p j;
    public int k;
    public boolean l;
    public androidx.compose.ui.semantics.k m;
    public final androidx.compose.runtime.collection.b n;
    public boolean o;
    public androidx.compose.ui.layout.K p;
    public androidx.compose.foundation.text.input.internal.u q;
    public androidx.compose.ui.unit.b r;
    public androidx.compose.ui.unit.k s;
    public Y0 t;
    public InterfaceC0837y u;
    public boolean v;
    public final V w;
    public final L x;
    public androidx.compose.ui.layout.G y;
    public a0 z;

    public E(int i) {
        this((i & 1) == 0, androidx.compose.ui.semantics.m.a.addAndGet(1));
    }

    public static boolean M(E e) {
        K k = e.x.r;
        return e.L(k.i ? new androidx.compose.ui.unit.a(k.d) : null);
    }

    public static void R(E e, boolean z, int i) {
        E eS;
        if ((i & 1) != 0) {
            z = false;
        }
        boolean z2 = (i & 2) != 0;
        boolean z3 = (i & 4) != 0;
        if (e.c == null) {
            W4.f("Lookahead measure cannot be requested on a node that is not a part of theLookaheadScope");
            throw null;
        }
        C0971v c0971v = e.i;
        if (c0971v == null || e.l || e.a) {
            return;
        }
        c0971v.w(e, true, z, z2);
        if (z3) {
            J j = e.x.s;
            Intrinsics.d(j);
            L l = j.y;
            E eS2 = l.a.s();
            int i2 = l.a.H;
            if (eS2 == null || i2 == 3) {
                return;
            }
            while (eS2.H == i2 && (eS = eS2.s()) != null) {
                eS2 = eS;
            }
            int iK = AbstractC0147y.k(i2);
            if (iK == 0) {
                if (eS2.c != null) {
                    R(eS2, z, 6);
                    return;
                } else {
                    T(eS2, z, 6);
                    return;
                }
            }
            if (iK != 1) {
                throw new IllegalStateException("Intrinsics isn't used by the parent");
            }
            if (eS2.c != null) {
                eS2.Q(z);
            } else {
                eS2.S(z);
            }
        }
    }

    public static void T(E e, boolean z, int i) {
        C0971v c0971v;
        E eS;
        if ((i & 1) != 0) {
            z = false;
        }
        boolean z2 = (i & 2) != 0;
        boolean z3 = (i & 4) != 0;
        if (e.l || e.a || (c0971v = e.i) == null) {
            return;
        }
        c0971v.w(e, false, z, z2);
        if (z3) {
            L l = e.x.r.H;
            E eS2 = l.a.s();
            int i2 = l.a.H;
            if (eS2 == null || i2 == 3) {
                return;
            }
            while (eS2.H == i2 && (eS = eS2.s()) != null) {
                eS2 = eS;
            }
            int iK = AbstractC0147y.k(i2);
            if (iK == 0) {
                T(eS2, z, 6);
            } else {
                if (iK != 1) {
                    throw new IllegalStateException("Intrinsics isn't used by the parent");
                }
                eS2.S(z);
            }
        }
    }

    public static void U(E e) {
        int i = D.a[AbstractC0147y.k(e.x.c)];
        L l = e.x;
        if (i != 1) {
            throw new IllegalStateException("Unexpected state ".concat(B.w(l.c)));
        }
        if (l.g) {
            R(e, true, 6);
            return;
        }
        if (l.h) {
            e.Q(true);
        }
        if (l.d) {
            T(e, true, 6);
        } else if (l.e) {
            e.S(true);
        }
    }

    public final void A() {
        V v = this.w;
        a0 a0Var = (a0) v.d;
        C0923t c0923t = (C0923t) v.c;
        while (a0Var != c0923t) {
            Intrinsics.e(a0Var, "null cannot be cast to non-null type androidx.compose.ui.node.LayoutModifierNodeCoordinator");
            C0928y c0928y = (C0928y) a0Var;
            f0 f0Var = c0928y.D;
            if (f0Var != null) {
                f0Var.invalidate();
            }
            a0Var = c0928y.m;
        }
        f0 f0Var2 = ((C0923t) v.c).D;
        if (f0Var2 != null) {
            f0Var2.invalidate();
        }
    }

    public final void B() {
        if (this.c != null) {
            R(this, false, 7);
        } else {
            T(this, false, 7);
        }
    }

    public final void C() {
        this.m = null;
        ((C0971v) H.a(this)).y();
    }

    public final void D() {
        E e;
        if (this.d > 0) {
            this.g = true;
        }
        if (!this.a || (e = this.h) == null) {
            return;
        }
        e.D();
    }

    public final boolean E() {
        return this.i != null;
    }

    public final boolean F() {
        return this.x.r.s;
    }

    public final Boolean G() {
        J j = this.x.s;
        if (j != null) {
            return Boolean.valueOf(j.q);
        }
        return null;
    }

    public final void H() {
        E eS;
        if (this.H == 3) {
            g();
        }
        J j = this.x.s;
        Intrinsics.d(j);
        try {
            j.f = true;
            if (!j.k) {
                W4.f("replace() called on item that was not placed");
                throw null;
            }
            j.x = false;
            boolean z = j.q;
            j.E0(j.n, j.o, j.p);
            if (z && !j.x && (eS = j.y.a.s()) != null) {
                eS.Q(false);
            }
        } finally {
            j.f = false;
        }
    }

    public final void I(int i, int i2, int i3) {
        if (i == i2) {
            return;
        }
        for (int i4 = 0; i4 < i3; i4++) {
            int i5 = i > i2 ? i + i4 : i;
            int i6 = i > i2 ? i2 + i4 : (i2 + i3) - 2;
            androidx.work.impl.model.c cVar = this.e;
            Object objO = ((androidx.compose.runtime.collection.b) cVar.b).o(i5);
            androidx.compose.ui.input.nestedscroll.b bVar = (androidx.compose.ui.input.nestedscroll.b) cVar.c;
            bVar.invoke();
            ((androidx.compose.runtime.collection.b) cVar.b).a(i6, (E) objO);
            bVar.invoke();
        }
        K();
        D();
        B();
    }

    public final void J(E e) {
        if (e.x.n > 0) {
            this.x.b(r0.n - 1);
        }
        if (this.i != null) {
            e.i();
        }
        e.h = null;
        ((a0) e.w.d).n = null;
        if (e.a) {
            this.d--;
            androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) e.e.b;
            int i = bVar.c;
            if (i > 0) {
                Object[] objArr = bVar.a;
                int i2 = 0;
                do {
                    ((a0) ((E) objArr[i2]).w.d).n = null;
                    i2++;
                } while (i2 < i);
            }
        }
        D();
        K();
    }

    public final void K() {
        if (!this.a) {
            this.o = true;
            return;
        }
        E eS = s();
        if (eS != null) {
            eS.K();
        }
    }

    public final boolean L(androidx.compose.ui.unit.a aVar) {
        if (aVar == null) {
            return false;
        }
        if (this.H == 3) {
            f();
        }
        return this.x.r.H0(aVar.a);
    }

    public final void N() {
        androidx.work.impl.model.c cVar = this.e;
        int i = ((androidx.compose.runtime.collection.b) cVar.b).c;
        while (true) {
            i--;
            androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) cVar.b;
            if (-1 >= i) {
                bVar.i();
                ((androidx.compose.ui.input.nestedscroll.b) cVar.c).invoke();
                return;
            }
            J((E) bVar.a[i]);
        }
    }

    public final void O(int i, int i2) {
        if (i2 < 0) {
            W4.e("count (" + i2 + ") must be greater than 0");
            throw null;
        }
        int i3 = (i2 + i) - 1;
        if (i > i3) {
            return;
        }
        while (true) {
            androidx.work.impl.model.c cVar = this.e;
            J((E) ((androidx.compose.runtime.collection.b) cVar.b).a[i3]);
            Object objO = ((androidx.compose.runtime.collection.b) cVar.b).o(i3);
            ((androidx.compose.ui.input.nestedscroll.b) cVar.c).invoke();
            if (i3 == i) {
                return;
            } else {
                i3--;
            }
        }
    }

    public final void P() {
        E eS;
        if (this.H == 3) {
            g();
        }
        K k = this.x.r;
        k.getClass();
        try {
            k.f = true;
            if (!k.j) {
                W4.f("replace called on unplaced item");
                throw null;
            }
            boolean z = k.s;
            k.F0(k.m, k.p, k.n, k.o);
            if (z && !k.A && (eS = k.H.a.s()) != null) {
                eS.S(false);
            }
        } finally {
            k.f = false;
        }
    }

    public final void Q(boolean z) {
        C0971v c0971v;
        if (this.a || (c0971v = this.i) == null) {
            return;
        }
        c0971v.x(this, true, z);
    }

    public final void S(boolean z) {
        C0971v c0971v;
        if (this.a || (c0971v = this.i) == null) {
            return;
        }
        c0971v.x(this, false, z);
    }

    public final void V() {
        androidx.compose.runtime.collection.b bVarW = w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e = (E) objArr[i2];
                int i3 = e.I;
                e.H = i3;
                if (i3 != 3) {
                    e.V();
                }
                i2++;
            } while (i2 < i);
        }
    }

    public final void W(androidx.compose.ui.unit.b bVar) {
        if (Intrinsics.b(this.r, bVar)) {
            return;
        }
        this.r = bVar;
        B();
        E eS = s();
        if (eS != null) {
            eS.z();
        }
        A();
        for (androidx.compose.ui.p pVar = (androidx.compose.ui.p) this.w.f; pVar != null; pVar = pVar.f) {
            if ((pVar.c & 16) != 0) {
                ((l0) pVar).X();
            } else if (pVar instanceof androidx.compose.ui.draw.c) {
                ((androidx.compose.ui.draw.c) pVar).M0();
            }
        }
    }

    public final void X(E e) {
        if (Intrinsics.b(e, this.c)) {
            return;
        }
        this.c = e;
        if (e != null) {
            L l = this.x;
            if (l.s == null) {
                l.s = new J(l);
            }
            V v = this.w;
            a0 a0Var = ((C0923t) v.c).m;
            for (a0 a0Var2 = (a0) v.d; !Intrinsics.b(a0Var2, a0Var) && a0Var2 != null; a0Var2 = a0Var2.m) {
                a0Var2.R0();
            }
        }
        B();
    }

    public final void Y(androidx.compose.ui.layout.K k) {
        if (Intrinsics.b(this.p, k)) {
            return;
        }
        this.p = k;
        androidx.compose.foundation.text.input.internal.u uVar = this.q;
        if (uVar != null) {
            ((L0) ((InterfaceC0773a0) uVar.c)).setValue(k);
        }
        B();
    }

    public final void Z(androidx.compose.ui.q qVar) {
        if (!(!this.a || this.B == androidx.compose.ui.n.b)) {
            W4.e("Modifiers are not supported on virtual LayoutNodes");
            throw null;
        }
        if (this.G) {
            W4.e("modifier is updated when deactivated");
            throw null;
        }
        if (E()) {
            c(qVar);
        } else {
            this.C = qVar;
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void a() {
        androidx.compose.ui.viewinterop.p pVar = this.j;
        if (pVar != null) {
            pVar.a();
        }
        androidx.compose.ui.layout.G g = this.y;
        if (g != null) {
            g.a();
        }
        V v = this.w;
        a0 a0Var = ((C0923t) v.c).m;
        for (a0 a0Var2 = (a0) v.d; !Intrinsics.b(a0Var2, a0Var) && a0Var2 != null; a0Var2 = a0Var2.m) {
            a0Var2.o = true;
            a0Var2.B.invoke();
            if (a0Var2.D != null) {
                if (a0Var2.E != null) {
                    a0Var2.E = null;
                }
                a0Var2.r1(null, false);
                a0Var2.l.S(false);
            }
        }
    }

    public final void a0() {
        if (this.d <= 0 || !this.g) {
            return;
        }
        int i = 0;
        this.g = false;
        androidx.compose.runtime.collection.b bVar = this.f;
        if (bVar == null) {
            bVar = new androidx.compose.runtime.collection.b(new E[16]);
            this.f = bVar;
        }
        bVar.i();
        androidx.compose.runtime.collection.b bVar2 = (androidx.compose.runtime.collection.b) this.e.b;
        int i2 = bVar2.c;
        if (i2 > 0) {
            Object[] objArr = bVar2.a;
            do {
                E e = (E) objArr[i];
                if (e.a) {
                    bVar.c(bVar.c, e.w());
                } else {
                    bVar.b(e);
                }
                i++;
            } while (i < i2);
        }
        L l = this.x;
        l.r.w = true;
        J j = l.s;
        if (j != null) {
            j.t = true;
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void b() {
        androidx.compose.ui.viewinterop.p pVar = this.j;
        if (pVar != null) {
            pVar.b();
        }
        androidx.compose.ui.layout.G g = this.y;
        if (g != null) {
            g.f(true);
        }
        this.G = true;
        V v = this.w;
        for (androidx.compose.ui.p pVar2 = (o0) v.e; pVar2 != null; pVar2 = pVar2.e) {
            if (pVar2.m) {
                pVar2.H0();
            }
        }
        androidx.compose.ui.p pVar3 = (o0) v.e;
        for (androidx.compose.ui.p pVar4 = pVar3; pVar4 != null; pVar4 = pVar4.e) {
            if (pVar4.m) {
                pVar4.J0();
            }
        }
        while (pVar3 != null) {
            if (pVar3.m) {
                pVar3.D0();
            }
            pVar3 = pVar3.e;
        }
        if (E()) {
            C();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:47:0x00c2, code lost:
    
        if (r2 >= r6) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00c4, code lost:
    
        if (r3 == null) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x00c6, code lost:
    
        if (r1 == null) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00ca, code lost:
    
        if (r13.C == null) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00cc, code lost:
    
        r4 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00ce, code lost:
    
        r4 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00cf, code lost:
    
        r6 = !r4;
        r5 = r1;
        r1 = r2;
        r4 = r8;
        r1.j(r2, r3, r4, r5, r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00da, code lost:
    
        com.google.android.gms.internal.mlkit_vision_barcode.W4.g("structuralUpdate requires a non-null tail");
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x00df, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00e0, code lost:
    
        com.google.android.gms.internal.mlkit_vision_barcode.W4.g("expected prior modifier list to be non-empty");
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00e3, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00e4, code lost:
    
        r2 = r2;
        r4 = r8;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v9, types: [androidx.compose.ui.p] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(androidx.compose.ui.q r18) {
        /*
            Method dump skipped, instructions count: 423
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.E.c(androidx.compose.ui.q):void");
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void d() {
        if (!E()) {
            W4.e("onReuse is only expected on attached node");
            throw null;
        }
        androidx.compose.ui.viewinterop.p pVar = this.j;
        if (pVar != null) {
            pVar.d();
        }
        androidx.compose.ui.layout.G g = this.y;
        if (g != null) {
            g.f(false);
        }
        boolean z = this.G;
        V v = this.w;
        if (z) {
            this.G = false;
            C();
        } else {
            for (androidx.compose.ui.p pVar2 = (o0) v.e; pVar2 != null; pVar2 = pVar2.e) {
                if (pVar2.m) {
                    pVar2.H0();
                }
            }
            androidx.compose.ui.p pVar3 = (o0) v.e;
            for (androidx.compose.ui.p pVar4 = pVar3; pVar4 != null; pVar4 = pVar4.e) {
                if (pVar4.m) {
                    pVar4.J0();
                }
            }
            while (pVar3 != null) {
                if (pVar3.m) {
                    pVar3.D0();
                }
                pVar3 = pVar3.e;
            }
        }
        this.b = androidx.compose.ui.semantics.m.a.addAndGet(1);
        for (androidx.compose.ui.p pVar5 = (androidx.compose.ui.p) v.f; pVar5 != null; pVar5 = pVar5.f) {
            pVar5.C0();
        }
        v.i();
        U(this);
    }

    public final void e(C0971v c0971v) {
        E e;
        if (!(this.i == null)) {
            W4.f("Cannot attach " + this + " as it already is attached.  Tree: " + h(0));
            throw null;
        }
        E e2 = this.h;
        if (e2 != null && !Intrinsics.b(e2.i, c0971v)) {
            StringBuilder sb = new StringBuilder("Attaching to a different owner(");
            sb.append(c0971v);
            sb.append(") than the parent's owner(");
            E eS = s();
            sb.append(eS != null ? eS.i : null);
            sb.append("). This tree: ");
            sb.append(h(0));
            sb.append(" Parent tree: ");
            E e3 = this.h;
            sb.append(e3 != null ? e3.h(0) : null);
            W4.f(sb.toString());
            throw null;
        }
        E eS2 = s();
        L l = this.x;
        if (eS2 == null) {
            l.r.s = true;
            J j = l.s;
            if (j != null) {
                j.q = true;
            }
        }
        V v = this.w;
        ((a0) v.d).n = eS2 != null ? (C0923t) eS2.w.c : null;
        this.i = c0971v;
        this.k = (eS2 != null ? eS2.k : -1) + 1;
        androidx.compose.ui.q qVar = this.C;
        if (qVar != null) {
            c(qVar);
        }
        this.C = null;
        if (v.h(8)) {
            C();
        }
        c0971v.getClass();
        E e4 = this.h;
        if (e4 == null || (e = e4.c) == null) {
            e = this.c;
        }
        X(e);
        if (this.c == null && v.h(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH)) {
            X(this);
        }
        if (!this.G) {
            for (androidx.compose.ui.p pVar = (androidx.compose.ui.p) v.f; pVar != null; pVar = pVar.f) {
                pVar.C0();
            }
        }
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.e.b;
        int i = bVar.c;
        if (i > 0) {
            Object[] objArr = bVar.a;
            int i2 = 0;
            do {
                ((E) objArr[i2]).e(c0971v);
                i2++;
            } while (i2 < i);
        }
        if (!this.G) {
            v.i();
        }
        B();
        if (eS2 != null) {
            eS2.B();
        }
        a0 a0Var = ((C0923t) v.c).m;
        for (a0 a0Var2 = (a0) v.d; !Intrinsics.b(a0Var2, a0Var) && a0Var2 != null; a0Var2 = a0Var2.m) {
            a0Var2.r1(a0Var2.q, true);
            f0 f0Var = a0Var2.D;
            if (f0Var != null) {
                f0Var.invalidate();
            }
        }
        androidx.compose.ui.viewinterop.c cVar = this.D;
        if (cVar != null) {
            cVar.invoke(c0971v);
        }
        l.h();
        if (this.G) {
            return;
        }
        androidx.compose.ui.p pVar2 = (androidx.compose.ui.p) v.f;
        if ((pVar2.d & 7168) != 0) {
            while (pVar2 != null) {
                int i3 = pVar2.c;
                if (((i3 & 4096) != 0) | ((i3 & 1024) != 0) | ((i3 & 2048) != 0)) {
                    b0.a(pVar2);
                }
                pVar2 = pVar2.f;
            }
        }
    }

    public final void f() {
        this.I = this.H;
        this.H = 3;
        androidx.compose.runtime.collection.b bVarW = w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e = (E) objArr[i2];
                if (e.H != 3) {
                    e.f();
                }
                i2++;
            } while (i2 < i);
        }
    }

    public final void g() {
        this.I = this.H;
        this.H = 3;
        androidx.compose.runtime.collection.b bVarW = w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e = (E) objArr[i2];
                if (e.H == 2) {
                    e.g();
                }
                i2++;
            } while (i2 < i);
        }
    }

    public final String h(int i) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < i; i2++) {
            sb.append("  ");
        }
        sb.append("|-");
        sb.append(toString());
        sb.append('\n');
        androidx.compose.runtime.collection.b bVarW = w();
        int i3 = bVarW.c;
        if (i3 > 0) {
            Object[] objArr = bVarW.a;
            int i4 = 0;
            do {
                sb.append(((E) objArr[i4]).h(i + 1));
                i4++;
            } while (i4 < i3);
        }
        String string = sb.toString();
        if (i != 0) {
            return string;
        }
        String strSubstring = string.substring(0, string.length() - 1);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public final void i() {
        F f;
        C0971v c0971v = this.i;
        if (c0971v == null) {
            StringBuilder sb = new StringBuilder("Cannot detach node that is already detached!  Tree: ");
            E eS = s();
            sb.append(eS != null ? eS.h(0) : null);
            W4.g(sb.toString());
            throw null;
        }
        E eS2 = s();
        L l = this.x;
        if (eS2 != null) {
            eS2.z();
            eS2.B();
            l.r.k = 3;
            J j = l.s;
            if (j != null) {
                j.i = 3;
            }
        }
        F f2 = l.r.u;
        f2.b = true;
        f2.c = false;
        f2.e = false;
        f2.d = false;
        f2.f = false;
        f2.g = false;
        f2.h = null;
        J j2 = l.s;
        if (j2 != null && (f = j2.r) != null) {
            f.b = true;
            f.c = false;
            f.e = false;
            f.d = false;
            f.f = false;
            f.g = false;
            f.h = null;
        }
        androidx.compose.ui.input.pointer.s sVar = this.E;
        if (sVar != null) {
            sVar.invoke(c0971v);
        }
        V v = this.w;
        if (v.h(8)) {
            C();
        }
        androidx.compose.ui.p pVar = (o0) v.e;
        for (androidx.compose.ui.p pVar2 = pVar; pVar2 != null; pVar2 = pVar2.e) {
            if (pVar2.m) {
                pVar2.J0();
            }
        }
        this.l = true;
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.e.b;
        int i = bVar.c;
        if (i > 0) {
            Object[] objArr = bVar.a;
            int i2 = 0;
            do {
                ((E) objArr[i2]).i();
                i2++;
            } while (i2 < i);
        }
        this.l = false;
        while (pVar != null) {
            if (pVar.m) {
                pVar.D0();
            }
            pVar = pVar.e;
        }
        S s = c0971v.H;
        com.quizlet.data.repository.widget.b bVar2 = s.b;
        ((com.quizlet.data.repository.searchexplanations.c) bVar2.b).k(this);
        ((com.quizlet.data.repository.searchexplanations.c) bVar2.c).k(this);
        ((androidx.compose.runtime.collection.b) s.e.b).n(this);
        c0971v.z = true;
        this.i = null;
        X(null);
        this.k = 0;
        K k = l.r;
        k.h = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        k.g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        k.s = false;
        J j3 = l.s;
        if (j3 != null) {
            j3.h = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            j3.g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            j3.q = false;
        }
    }

    public final void j(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        ((a0) this.w.d).O0(interfaceC0858s, bVar);
    }

    public final void k() {
        if (this.c != null) {
            R(this, false, 5);
        } else {
            T(this, false, 5);
        }
        K k = this.x.r;
        androidx.compose.ui.unit.a aVar = k.i ? new androidx.compose.ui.unit.a(k.d) : null;
        if (aVar != null) {
            C0971v c0971v = this.i;
            if (c0971v != null) {
                c0971v.r(this, aVar.a);
                return;
            }
            return;
        }
        C0971v c0971v2 = this.i;
        if (c0971v2 != null) {
            c0971v2.q(true);
        }
    }

    public final List l() {
        J j = this.x.s;
        Intrinsics.d(j);
        L l = j.y;
        l.a.n();
        boolean z = j.t;
        androidx.compose.runtime.collection.b bVar = j.s;
        if (!z) {
            return bVar.h();
        }
        E e = l.a;
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (bVar.c <= i2) {
                    J j2 = e2.x.s;
                    Intrinsics.d(j2);
                    bVar.b(j2);
                } else {
                    J j3 = e2.x.s;
                    Intrinsics.d(j3);
                    Object[] objArr2 = bVar.a;
                    Object obj = objArr2[i2];
                    objArr2[i2] = j3;
                }
                i2++;
            } while (i2 < i);
        }
        bVar.p(((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.n()).b).c, bVar.c);
        j.t = false;
        return bVar.h();
    }

    public final List m() {
        return this.x.r.y0();
    }

    public final List n() {
        return w().h();
    }

    public final androidx.compose.ui.semantics.k o() {
        if (!E() || this.G) {
            return null;
        }
        if (!this.w.h(8) || this.m != null) {
            return this.m;
        }
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        j.a = new androidx.compose.ui.semantics.k();
        i0 snapshotObserver = ((C0971v) H.a(this)).getSnapshotObserver();
        snapshotObserver.a(this, snapshotObserver.d, new C0242g(20, this, j));
        androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) j.a;
        this.m = kVar;
        return kVar;
    }

    public final List p() {
        return ((androidx.compose.runtime.collection.b) this.e.b).h();
    }

    public final int q() {
        int i;
        J j = this.x.s;
        if (j == null || (i = j.i) == 0) {
            return 3;
        }
        return i;
    }

    public final androidx.compose.foundation.text.input.internal.u r() {
        androidx.compose.foundation.text.input.internal.u uVar = this.q;
        if (uVar != null) {
            return uVar;
        }
        androidx.compose.foundation.text.input.internal.u uVar2 = new androidx.compose.foundation.text.input.internal.u(this, this.p);
        this.q = uVar2;
        return uVar2;
    }

    public final E s() {
        E e = this.h;
        while (e != null && e.a) {
            e = e.h;
        }
        return e;
    }

    public final int t() {
        return this.x.r.h;
    }

    public final String toString() {
        return androidx.compose.ui.platform.N.F(this) + " children: " + ((androidx.compose.runtime.collection.b) ((androidx.collection.E) n()).b).c + " measurePolicy: " + this.p;
    }

    @Override // androidx.compose.ui.node.h0
    public final boolean u() {
        return E();
    }

    public final androidx.compose.runtime.collection.b v() {
        boolean z = this.o;
        androidx.compose.runtime.collection.b bVar = this.n;
        if (z) {
            bVar.i();
            bVar.c(bVar.c, w());
            bVar.s(L);
            this.o = false;
        }
        return bVar;
    }

    public final androidx.compose.runtime.collection.b w() {
        a0();
        if (this.d == 0) {
            return (androidx.compose.runtime.collection.b) this.e.b;
        }
        androidx.compose.runtime.collection.b bVar = this.f;
        Intrinsics.d(bVar);
        return bVar;
    }

    public final void x(long j, r rVar, boolean z, boolean z2) {
        V v = this.w;
        a0 a0Var = (a0) v.d;
        androidx.compose.ui.graphics.S s = a0.F;
        ((a0) v.d).a1(a0.I, a0Var.T0(j), rVar, z, z2);
    }

    public final void y(int i, E e) {
        if (!(e.h == null)) {
            StringBuilder sb = new StringBuilder("Cannot insert ");
            sb.append(e);
            sb.append(" because it already has a parent. This tree: ");
            sb.append(h(0));
            sb.append(" Other tree: ");
            E e2 = e.h;
            sb.append(e2 != null ? e2.h(0) : null);
            W4.f(sb.toString());
            throw null;
        }
        if (e.i != null) {
            W4.f("Cannot insert " + e + " because it already has an owner. This tree: " + h(0) + " Other tree: " + e.h(0));
            throw null;
        }
        e.h = this;
        androidx.work.impl.model.c cVar = this.e;
        ((androidx.compose.runtime.collection.b) cVar.b).a(i, e);
        ((androidx.compose.ui.input.nestedscroll.b) cVar.c).invoke();
        K();
        if (e.a) {
            this.d++;
        }
        D();
        C0971v c0971v = this.i;
        if (c0971v != null) {
            e.e(c0971v);
        }
        if (e.x.n > 0) {
            L l = this.x;
            l.b(l.n + 1);
        }
    }

    public final void z() {
        if (this.A) {
            V v = this.w;
            a0 a0Var = (C0923t) v.c;
            a0 a0Var2 = ((a0) v.d).n;
            this.z = null;
            while (true) {
                if (Intrinsics.b(a0Var, a0Var2)) {
                    break;
                }
                if ((a0Var != null ? a0Var.D : null) != null) {
                    this.z = a0Var;
                    break;
                }
                a0Var = a0Var != null ? a0Var.n : null;
            }
        }
        a0 a0Var3 = this.z;
        if (a0Var3 != null && a0Var3.D == null) {
            W4.g("layer was not set");
            throw null;
        }
        if (a0Var3 != null) {
            a0Var3.c1();
            return;
        }
        E eS = s();
        if (eS != null) {
            eS.z();
        }
    }

    public E(boolean z, int i) {
        this.a = z;
        this.b = i;
        int i2 = 4;
        this.e = new androidx.work.impl.model.c(i2, new androidx.compose.runtime.collection.b(new E[16]), new androidx.compose.ui.input.nestedscroll.b(this, i2));
        this.n = new androidx.compose.runtime.collection.b(new E[16]);
        this.o = true;
        this.p = J;
        this.r = H.a;
        this.s = androidx.compose.ui.unit.k.a;
        this.t = K;
        InterfaceC0837y.C0.getClass();
        this.u = C0835x.b;
        this.H = 3;
        this.I = 3;
        this.w = new V(this);
        this.x = new L(this);
        this.A = true;
        this.B = androidx.compose.ui.n.b;
    }
}
