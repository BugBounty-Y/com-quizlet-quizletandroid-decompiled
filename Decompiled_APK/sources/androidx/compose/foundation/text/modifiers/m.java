package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.d0;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.selection.C0532m;
import androidx.compose.foundation.text.selection.C0535p;
import androidx.compose.foundation.text.selection.C0536q;
import androidx.compose.foundation.text.selection.b0;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.G;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.InterfaceC0926w;
import androidx.compose.ui.node.O;
import androidx.compose.ui.node.n0;
import androidx.compose.ui.semantics.r;
import androidx.compose.ui.semantics.t;
import androidx.compose.ui.semantics.u;
import androidx.compose.ui.semantics.v;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.D;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3227p0;
import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.Map;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m extends androidx.compose.ui.p implements InterfaceC0926w, InterfaceC0919o, n0 {
    public d A;
    public l B;
    public k C;
    public C0995g n;
    public L o;
    public androidx.compose.ui.text.font.i p;
    public Function1 q;
    public int r;
    public boolean s;
    public int t;
    public int u;
    public List v;
    public Function1 w;
    public h x;
    public Function1 y;
    public Map z;

    public m(C0995g c0995g, L l, androidx.compose.ui.text.font.i iVar, Function1 function1, int i, boolean z, int i2, int i3, List list, Function1 function12, h hVar, Function1 function13) {
        this.n = c0995g;
        this.o = l;
        this.p = iVar;
        this.q = function1;
        this.r = i;
        this.s = z;
        this.t = i2;
        this.u = i3;
        this.v = list;
        this.w = function12;
        this.x = hVar;
        this.y = function13;
    }

    public final void M0(boolean z, boolean z2, boolean z3, boolean z4) {
        if (z2 || z3 || z4) {
            d dVarN0 = N0();
            C0995g c0995g = this.n;
            L l = this.o;
            androidx.compose.ui.text.font.i iVar = this.p;
            int i = this.r;
            boolean z5 = this.s;
            int i2 = this.t;
            int i3 = this.u;
            List list = this.v;
            dVarN0.a = c0995g;
            dVarN0.b = l;
            dVarN0.c = iVar;
            dVarN0.d = i;
            dVarN0.e = z5;
            dVarN0.f = i2;
            dVarN0.g = i3;
            dVarN0.h = list;
            dVarN0.l = null;
            dVarN0.n = null;
            dVarN0.p = -1;
            dVarN0.o = -1;
        }
        if (this.m) {
            if (z2 || (z && this.B != null)) {
                AbstractC0910f.p(this);
            }
            if (z2 || z3 || z4) {
                AbstractC0910f.o(this);
                AbstractC0910f.n(this);
            }
            if (z) {
                AbstractC0910f.n(this);
            }
        }
    }

    public final d N0() {
        if (this.A == null) {
            this.A = new d(this.n, this.o, this.p, this.r, this.s, this.t, this.u, this.v);
        }
        d dVar = this.A;
        Intrinsics.d(dVar);
        return dVar;
    }

    public final d O0(androidx.compose.ui.unit.b bVar) {
        d dVar;
        k kVar = this.C;
        if (kVar != null && kVar.c && (dVar = kVar.d) != null) {
            dVar.c(bVar);
            return dVar;
        }
        d dVarN0 = N0();
        dVarN0.c(bVar);
        return dVarN0;
    }

    public final boolean P0(Function1 function1, Function1 function12, h hVar, Function1 function13) {
        boolean z;
        if (this.q != function1) {
            this.q = function1;
            z = true;
        } else {
            z = false;
        }
        if (this.w != function12) {
            this.w = function12;
            z = true;
        }
        if (!Intrinsics.b(this.x, hVar)) {
            this.x = hVar;
            z = true;
        }
        if (this.y == function13) {
            return z;
        }
        this.y = function13;
        return true;
    }

    public final boolean Q0(L l, List list, int i, int i2, boolean z, androidx.compose.ui.text.font.i iVar, int i3) {
        boolean z2 = !this.o.d(l);
        this.o = l;
        if (!Intrinsics.b(this.v, list)) {
            this.v = list;
            z2 = true;
        }
        if (this.u != i) {
            this.u = i;
            z2 = true;
        }
        if (this.t != i2) {
            this.t = i2;
            z2 = true;
        }
        if (this.s != z) {
            this.s = z;
            z2 = true;
        }
        if (!Intrinsics.b(this.p, iVar)) {
            this.p = iVar;
            z2 = true;
        }
        if (this.r == i3) {
            return z2;
        }
        this.r = i3;
        return true;
    }

    public final boolean R0(C0995g c0995g) {
        boolean zB = Intrinsics.b(this.n.a, c0995g.a);
        boolean zB2 = Intrinsics.b(this.n.b(), c0995g.b());
        Object obj = this.n.c;
        if (obj == null) {
            obj = K.a;
        }
        Object obj2 = c0995g.c;
        if (obj2 == null) {
            obj2 = K.a;
        }
        boolean z = (zB && zB2 && Intrinsics.b(obj, obj2) && Intrinsics.b(this.n.d, c0995g.d)) ? false : true;
        if (z) {
            this.n = c0995g;
        }
        if (!zB) {
            this.C = null;
        }
        return z;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(O o, J j, int i) {
        return AbstractC0484d0.q(O0(o).d(o.getLayoutDirection()).d());
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(O o, J j, int i) {
        return AbstractC0484d0.q(O0(o).d(o.getLayoutDirection()).b());
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) throws Throwable {
        C0536q c0536q;
        com.quizlet.data.repository.folderset.c cVar;
        long j;
        H h;
        if (this.m) {
            h hVar = this.x;
            androidx.compose.ui.graphics.drawscope.b bVar = g.a;
            if (hVar != null && (c0536q = (C0536q) ((b0) hVar.b).a().d(hVar.a)) != null) {
                C0535p c0535p = c0536q.b;
                C0535p c0535p2 = c0536q.a;
                boolean z = c0536q.c;
                int i = !z ? c0535p2.b : c0535p.b;
                int i2 = !z ? c0535p.b : c0535p2.b;
                if (i != i2) {
                    C0532m c0532m = hVar.e;
                    int iB = (c0532m == null || (h = (H) c0532m.c.invoke()) == null) ? 0 : c0532m.b(h);
                    if (i > iB) {
                        i = iB;
                    }
                    if (i2 > iB) {
                        i2 = iB;
                    }
                    H h2 = hVar.d.b;
                    C0850j c0850jK = h2 != null ? h2.k(i, i2) : null;
                    if (c0850jK != null) {
                        H h3 = hVar.d.b;
                        if (h3 == null || h3.a.f == 3 || !h3.d()) {
                            androidx.compose.ui.graphics.drawscope.d.j(g, c0850jK, hVar.c, DefinitionKt.NO_Float_VALUE, null, 60);
                        } else {
                            float fD = androidx.compose.ui.geometry.e.d(bVar.g());
                            float fB = androidx.compose.ui.geometry.e.b(bVar.g());
                            com.quizlet.data.repository.folderset.c cVar2 = bVar.b;
                            long jR = cVar2.r();
                            cVar2.o().e();
                            try {
                                ((androidx.appcompat.app.L) cVar2.b).H(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, fD, fB, 1);
                                try {
                                    j = jR;
                                    cVar = cVar2;
                                    try {
                                        androidx.compose.ui.graphics.drawscope.d.j(g, c0850jK, hVar.c, DefinitionKt.NO_Float_VALUE, null, 60);
                                        d0.y(cVar, j);
                                    } catch (Throwable th) {
                                        th = th;
                                        d0.y(cVar, j);
                                        throw th;
                                    }
                                } catch (Throwable th2) {
                                    th = th2;
                                    cVar = cVar2;
                                    j = jR;
                                }
                            } catch (Throwable th3) {
                                th = th3;
                                cVar = cVar2;
                                j = jR;
                            }
                        }
                    }
                }
            }
            InterfaceC0858s interfaceC0858sO = bVar.b.o();
            H h4 = O0(g).n;
            if (h4 == null) {
                throw new IllegalStateException("You must call layoutWithConstraints first");
            }
            boolean z2 = h4.d() && this.r != 3;
            if (z2) {
                long j2 = h4.c;
                androidx.compose.ui.geometry.c cVarA = R4.a(0L, T4.a((int) (j2 >> 32), (int) (j2 & 4294967295L)));
                interfaceC0858sO.e();
                InterfaceC0858s.k(interfaceC0858sO, cVarA);
            }
            try {
                D d = this.o.a;
                androidx.compose.ui.text.style.j jVar = d.m;
                if (jVar == null) {
                    jVar = androidx.compose.ui.text.style.j.b;
                }
                androidx.compose.ui.text.style.j jVar2 = jVar;
                U u = d.n;
                if (u == null) {
                    u = U.d;
                }
                U u2 = u;
                androidx.compose.ui.graphics.drawscope.e eVar = d.p;
                if (eVar == null) {
                    eVar = androidx.compose.ui.graphics.drawscope.g.a;
                }
                androidx.compose.ui.graphics.drawscope.e eVar2 = eVar;
                AbstractC0857q abstractC0857qC = d.a.c();
                androidx.compose.ui.text.o oVar = h4.b;
                if (abstractC0857qC != null) {
                    androidx.compose.ui.text.o.h(oVar, interfaceC0858sO, abstractC0857qC, this.o.a.a.a(), u2, jVar2, eVar2);
                } else {
                    long jC = C0861v.g;
                    if (jC == 16) {
                        jC = this.o.c() != 16 ? this.o.c() : C0861v.b;
                    }
                    androidx.compose.ui.text.o.g(oVar, interfaceC0858sO, jC, u2, jVar2, eVar2);
                }
                if (z2) {
                    interfaceC0858sO.q();
                }
                k kVar = this.C;
                if (!((kVar == null || !kVar.c) ? AbstractC3227p0.c(this.n) : false)) {
                    List list = this.v;
                    if (list == null || list.isEmpty()) {
                        return;
                    }
                }
                g.b();
            } catch (Throwable th4) {
                if (z2) {
                    interfaceC0858sO.q();
                }
                throw th4;
            }
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(O o, J j, int i) {
        return O0(o).a(i, o.getLayoutDirection());
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x007f  */
    @Override // androidx.compose.ui.node.InterfaceC0926w
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M r8, androidx.compose.ui.layout.J r9, long r10) {
        /*
            Method dump skipped, instructions count: 351
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.modifiers.m.h(androidx.compose.ui.layout.M, androidx.compose.ui.layout.J, long):androidx.compose.ui.layout.L");
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(O o, J j, int i) {
        return O0(o).a(i, o.getLayoutDirection());
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(v vVar) {
        l lVar = this.B;
        if (lVar == null) {
            lVar = new l(this, 0);
            this.B = lVar;
        }
        t.j(vVar, this.n);
        k kVar = this.C;
        if (kVar != null) {
            C0995g c0995g = kVar.b;
            u uVar = r.v;
            kotlin.reflect.n[] nVarArr = t.a;
            kotlin.reflect.n nVar = nVarArr[14];
            uVar.a(vVar, c0995g);
            boolean z = kVar.c;
            u uVar2 = r.w;
            kotlin.reflect.n nVar2 = nVarArr[15];
            uVar2.a(vVar, Boolean.valueOf(z));
        }
        l lVar2 = new l(this, 1);
        u uVar3 = androidx.compose.ui.semantics.j.j;
        androidx.compose.ui.semantics.a aVar = new androidx.compose.ui.semantics.a(null, lVar2);
        androidx.compose.ui.semantics.k kVar2 = (androidx.compose.ui.semantics.k) vVar;
        kVar2.b(uVar3, aVar);
        kVar2.b(androidx.compose.ui.semantics.j.k, new androidx.compose.ui.semantics.a(null, new l(this, 2)));
        kVar2.b(androidx.compose.ui.semantics.j.l, new androidx.compose.ui.semantics.a(null, new androidx.compose.animation.core.K(this, 15)));
        t.c(vVar, lVar);
    }
}
