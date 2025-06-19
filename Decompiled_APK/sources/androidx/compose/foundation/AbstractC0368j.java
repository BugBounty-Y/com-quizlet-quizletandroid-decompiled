package androidx.compose.foundation;

import android.view.KeyEvent;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.InterfaceC0917m;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0368j extends AbstractC0918n implements androidx.compose.ui.node.l0, androidx.compose.ui.input.key.d, androidx.compose.ui.focus.d, androidx.compose.ui.node.n0, androidx.compose.ui.node.q0 {
    public static final z0 G = new z0(2);
    public androidx.compose.foundation.interaction.h A;
    public androidx.compose.foundation.interaction.l D;
    public boolean E;
    public final z0 F;
    public androidx.compose.foundation.interaction.l p;
    public InterfaceC0461p0 q;
    public String r;
    public androidx.compose.ui.semantics.h s;
    public boolean t;
    public Function0 u;
    public final W w;
    public androidx.compose.ui.input.pointer.B x;
    public InterfaceC0917m y;
    public androidx.compose.foundation.interaction.o z;
    public final Q v = new Q();
    public final LinkedHashMap B = new LinkedHashMap();
    public long C = 0;

    public AbstractC0368j(androidx.compose.foundation.interaction.l lVar, InterfaceC0461p0 interfaceC0461p0, boolean z, String str, androidx.compose.ui.semantics.h hVar, Function0 function0) {
        this.p = lVar;
        this.q = interfaceC0461p0;
        this.r = str;
        this.s = hVar;
        this.t = z;
        this.u = function0;
        this.w = new W(lVar);
        androidx.compose.foundation.interaction.l lVar2 = this.p;
        this.D = lVar2;
        this.E = lVar2 == null && this.q != null;
        this.F = G;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0066  */
    @Override // androidx.compose.ui.input.key.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean B(android.view.KeyEvent r13) {
        /*
            r12 = this;
            r12.S0()
            boolean r0 = r12.t
            java.util.LinkedHashMap r1 = r12.B
            r2 = 3
            r3 = 160(0xa0, float:2.24E-43)
            r4 = 66
            r5 = 23
            r6 = 32
            r7 = 0
            r8 = 1
            r9 = 0
            if (r0 == 0) goto L66
            int r0 = androidx.compose.foundation.F.b
            int r0 = androidx.compose.ui.input.key.c.c(r13)
            r10 = 2
            if (r0 != r10) goto L66
            long r10 = androidx.compose.ui.input.key.c.b(r13)
            long r10 = r10 >> r6
            int r0 = (int) r10
            if (r0 == r5) goto L2b
            if (r0 == r4) goto L2b
            if (r0 == r3) goto L2b
            goto L66
        L2b:
            int r0 = r13.getKeyCode()
            long r3 = androidx.compose.ui.input.key.c.a(r0)
            androidx.compose.ui.input.key.a r0 = new androidx.compose.ui.input.key.a
            r0.<init>(r3)
            boolean r0 = r1.containsKey(r0)
            if (r0 != 0) goto Laa
            androidx.compose.foundation.interaction.o r0 = new androidx.compose.foundation.interaction.o
            long r3 = r12.C
            r0.<init>(r3)
            int r13 = r13.getKeyCode()
            long r3 = androidx.compose.ui.input.key.c.a(r13)
            androidx.compose.ui.input.key.a r13 = new androidx.compose.ui.input.key.a
            r13.<init>(r3)
            r1.put(r13, r0)
            androidx.compose.foundation.interaction.l r13 = r12.p
            if (r13 == 0) goto L65
            kotlinx.coroutines.C r13 = r12.A0()
            androidx.compose.foundation.e r1 = new androidx.compose.foundation.e
            r1.<init>(r12, r0, r9)
            kotlinx.coroutines.E.A(r13, r9, r9, r1, r2)
        L65:
            return r8
        L66:
            boolean r0 = r12.t
            if (r0 == 0) goto Laa
            int r0 = androidx.compose.foundation.F.b
            int r0 = androidx.compose.ui.input.key.c.c(r13)
            if (r0 != r8) goto Laa
            long r10 = androidx.compose.ui.input.key.c.b(r13)
            long r10 = r10 >> r6
            int r0 = (int) r10
            if (r0 == r5) goto L7f
            if (r0 == r4) goto L7f
            if (r0 == r3) goto L7f
            return r7
        L7f:
            int r13 = r13.getKeyCode()
            long r3 = androidx.compose.ui.input.key.c.a(r13)
            androidx.compose.ui.input.key.a r13 = new androidx.compose.ui.input.key.a
            r13.<init>(r3)
            java.lang.Object r13 = r1.remove(r13)
            androidx.compose.foundation.interaction.o r13 = (androidx.compose.foundation.interaction.o) r13
            if (r13 == 0) goto La4
            androidx.compose.foundation.interaction.l r0 = r12.p
            if (r0 == 0) goto La4
            kotlinx.coroutines.C r0 = r12.A0()
            androidx.compose.foundation.f r1 = new androidx.compose.foundation.f
            r1.<init>(r12, r13, r9)
            kotlinx.coroutines.E.A(r0, r9, r9, r1, r2)
        La4:
            kotlin.jvm.functions.Function0 r13 = r12.u
            r13.invoke()
            return r8
        Laa:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.AbstractC0368j.B(android.view.KeyEvent):boolean");
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.node.l0
    public final void E(androidx.compose.ui.input.pointer.f fVar, androidx.compose.ui.input.pointer.g gVar, long j) {
        long j2 = ((j >> 33) << 32) | (((j << 32) >> 33) & 4294967295L);
        this.C = Q4.c((int) (j2 >> 32), (int) (j2 & 4294967295L));
        S0();
        if (this.t && gVar == androidx.compose.ui.input.pointer.g.b) {
            int i = fVar.d;
            if (i == 4) {
                kotlinx.coroutines.E.A(A0(), null, null, new C0311g(this, null), 3);
            } else if (i == 5) {
                kotlinx.coroutines.E.A(A0(), null, null, new C0364h(this, null), 3);
            }
        }
        if (this.x == null) {
            C0366i c0366i = new C0366i(this, null);
            androidx.compose.ui.input.pointer.f fVar2 = androidx.compose.ui.input.pointer.v.a;
            androidx.compose.ui.input.pointer.B b = new androidx.compose.ui.input.pointer.B(null, null, c0366i);
            M0(b);
            this.x = b;
        }
        androidx.compose.ui.input.pointer.B b2 = this.x;
        if (b2 != null) {
            b2.E(fVar, gVar, j);
        }
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        if (!this.E) {
            S0();
        }
        if (this.t) {
            M0(this.v);
            M0(this.w);
        }
    }

    @Override // androidx.compose.ui.node.l0
    public final void F() {
        androidx.compose.foundation.interaction.h hVar;
        androidx.compose.foundation.interaction.l lVar = this.p;
        if (lVar != null && (hVar = this.A) != null) {
            lVar.a(new androidx.compose.foundation.interaction.i(hVar));
        }
        this.A = null;
        androidx.compose.ui.input.pointer.B b = this.x;
        if (b != null) {
            b.F();
        }
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        R0();
        if (this.D == null) {
            this.p = null;
        }
        InterfaceC0917m interfaceC0917m = this.y;
        if (interfaceC0917m != null) {
            N0(interfaceC0917m);
        }
        this.y = null;
    }

    public void P0(androidx.compose.ui.semantics.v vVar) {
    }

    public abstract Object Q0(androidx.compose.ui.input.pointer.B b, C0366i c0366i);

    public final void R0() {
        androidx.compose.foundation.interaction.l lVar = this.p;
        LinkedHashMap linkedHashMap = this.B;
        if (lVar != null) {
            androidx.compose.foundation.interaction.o oVar = this.z;
            if (oVar != null) {
                lVar.a(new androidx.compose.foundation.interaction.n(oVar));
            }
            androidx.compose.foundation.interaction.h hVar = this.A;
            if (hVar != null) {
                lVar.a(new androidx.compose.foundation.interaction.i(hVar));
            }
            Iterator it2 = linkedHashMap.values().iterator();
            while (it2.hasNext()) {
                lVar.a(new androidx.compose.foundation.interaction.n((androidx.compose.foundation.interaction.o) it2.next()));
            }
        }
        this.z = null;
        this.A = null;
        linkedHashMap.clear();
    }

    public final void S0() {
        InterfaceC0461p0 interfaceC0461p0;
        if (this.y == null && (interfaceC0461p0 = this.q) != null) {
            if (this.p == null) {
                this.p = new androidx.compose.foundation.interaction.m();
            }
            this.w.P0(this.p);
            androidx.compose.foundation.interaction.l lVar = this.p;
            Intrinsics.d(lVar);
            InterfaceC0917m interfaceC0917mB = interfaceC0461p0.b(lVar);
            M0(interfaceC0917mB);
            this.y = interfaceC0917mB;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x0079  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void T0(androidx.compose.foundation.interaction.l r4, androidx.compose.foundation.InterfaceC0461p0 r5, boolean r6, java.lang.String r7, androidx.compose.ui.semantics.h r8, kotlin.jvm.functions.Function0 r9) {
        /*
            r3 = this;
            androidx.compose.foundation.interaction.l r0 = r3.D
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r0, r4)
            r1 = 0
            r2 = 1
            if (r0 != 0) goto L13
            r3.R0()
            r3.D = r4
            r3.p = r4
            r4 = r2
            goto L14
        L13:
            r4 = r1
        L14:
            androidx.compose.foundation.p0 r0 = r3.q
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r0, r5)
            if (r0 != 0) goto L1f
            r3.q = r5
            r4 = r2
        L1f:
            boolean r5 = r3.t
            androidx.compose.foundation.W r0 = r3.w
            if (r5 == r6) goto L3e
            androidx.compose.foundation.Q r5 = r3.v
            if (r6 == 0) goto L30
            r3.M0(r5)
            r3.M0(r0)
            goto L39
        L30:
            r3.N0(r5)
            r3.N0(r0)
            r3.R0()
        L39:
            androidx.compose.ui.node.AbstractC0910f.p(r3)
            r3.t = r6
        L3e:
            java.lang.String r5 = r3.r
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r7)
            if (r5 != 0) goto L4b
            r3.r = r7
            androidx.compose.ui.node.AbstractC0910f.p(r3)
        L4b:
            androidx.compose.ui.semantics.h r5 = r3.s
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r8)
            if (r5 != 0) goto L58
            r3.s = r8
            androidx.compose.ui.node.AbstractC0910f.p(r3)
        L58:
            r3.u = r9
            boolean r5 = r3.E
            androidx.compose.foundation.interaction.l r6 = r3.D
            if (r6 != 0) goto L66
            androidx.compose.foundation.p0 r7 = r3.q
            if (r7 == 0) goto L66
            r7 = r2
            goto L67
        L66:
            r7 = r1
        L67:
            if (r5 == r7) goto L79
            if (r6 != 0) goto L70
            androidx.compose.foundation.p0 r5 = r3.q
            if (r5 == 0) goto L70
            r1 = r2
        L70:
            r3.E = r1
            if (r1 != 0) goto L79
            androidx.compose.ui.node.m r5 = r3.y
            if (r5 != 0) goto L79
            goto L7a
        L79:
            r2 = r4
        L7a:
            if (r2 == 0) goto L8f
            androidx.compose.ui.node.m r4 = r3.y
            if (r4 != 0) goto L84
            boolean r5 = r3.E
            if (r5 != 0) goto L8f
        L84:
            if (r4 == 0) goto L89
            r3.N0(r4)
        L89:
            r4 = 0
            r3.y = r4
            r3.S0()
        L8f:
            androidx.compose.foundation.interaction.l r4 = r3.p
            r0.P0(r4)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.AbstractC0368j.T0(androidx.compose.foundation.interaction.l, androidx.compose.foundation.p0, boolean, java.lang.String, androidx.compose.ui.semantics.h, kotlin.jvm.functions.Function0):void");
    }

    @Override // androidx.compose.ui.focus.d
    public final void d0(androidx.compose.ui.focus.s sVar) {
        if (sVar.a()) {
            S0();
        }
        if (this.t) {
            this.w.d0(sVar);
        }
    }

    @Override // androidx.compose.ui.input.key.d
    public final boolean k(KeyEvent keyEvent) {
        return false;
    }

    @Override // androidx.compose.ui.node.q0
    public final Object m() {
        return this.F;
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        androidx.compose.ui.semantics.h hVar = this.s;
        if (hVar != null) {
            androidx.compose.ui.semantics.t.h(vVar, hVar.a);
        }
        String str = this.r;
        androidx.compose.animation.core.K k = new androidx.compose.animation.core.K(this, 2);
        kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.j.b;
        androidx.compose.ui.semantics.a aVar = new androidx.compose.ui.semantics.a(str, k);
        androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
        kVar.b(uVar, aVar);
        if (this.t) {
            this.w.r0(vVar);
        } else {
            kVar.b(androidx.compose.ui.semantics.r.i, Unit.a);
        }
        P0(vVar);
    }

    @Override // androidx.compose.ui.node.n0
    public final boolean x0() {
        return true;
    }
}
