package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.C;
import androidx.compose.animation.core.K;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.layout.AbstractC0882c;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
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
import androidx.compose.ui.text.C0982b;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.D;
import androidx.compose.ui.text.L;
import androidx.compose.ui.text.android.x;
import androidx.compose.ui.text.s;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3218o0;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p extends androidx.compose.ui.p implements InterfaceC0926w, InterfaceC0919o, n0 {
    public String n;
    public L o;
    public androidx.compose.ui.text.font.i p;
    public int q;
    public boolean r;
    public int s;
    public int t;
    public Map u;
    public e v;
    public o w;
    public n x;

    public final e M0() {
        if (this.v == null) {
            this.v = new e(this.n, this.o, this.p, this.q, this.r, this.s, this.t);
        }
        e eVar = this.v;
        Intrinsics.d(eVar);
        return eVar;
    }

    public final e N0(androidx.compose.ui.unit.b bVar) {
        e eVar;
        n nVar = this.x;
        if (nVar != null && nVar.c && (eVar = nVar.d) != null) {
            eVar.c(bVar);
            return eVar;
        }
        e eVarM0 = M0();
        eVarM0.c(bVar);
        return eVarM0;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(O o, J j, int i) {
        return AbstractC0484d0.q(N0(o).d(o.getLayoutDirection()).d());
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(O o, J j, int i) {
        return AbstractC0484d0.q(N0(o).d(o.getLayoutDirection()).b());
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) {
        if (this.m) {
            e eVarN0 = N0(g);
            C0982b c0982b = eVarN0.j;
            if (c0982b == null) {
                throw new IllegalArgumentException(("no paragraph (layoutCache=" + this.v + ", textSubstitution=" + this.x + ')').toString());
            }
            InterfaceC0858s interfaceC0858sO = g.a.b.o();
            boolean z = eVarN0.k;
            if (z) {
                long j = eVarN0.l;
                interfaceC0858sO.e();
                interfaceC0858sO.o(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (int) (j >> 32), (int) (j & 4294967295L), 1);
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
                if (abstractC0857qC != null) {
                    c0982b.g(interfaceC0858sO, abstractC0857qC, this.o.a.a.a(), u2, jVar2, eVar2);
                } else {
                    long jC = C0861v.g;
                    if (jC == 16) {
                        jC = this.o.c() != 16 ? this.o.c() : C0861v.b;
                    }
                    c0982b.f(interfaceC0858sO, jC, u2, jVar2, eVar2);
                }
                if (z) {
                    interfaceC0858sO.q();
                }
            } catch (Throwable th) {
                if (z) {
                    interfaceC0858sO.q();
                }
                throw th;
            }
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(O o, J j, int i) {
        return N0(o).a(i, o.getLayoutDirection());
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(M m, J j, long j2) {
        long jA;
        boolean z;
        s sVar;
        e eVarN0 = N0(m);
        androidx.compose.ui.unit.k layoutDirection = m.getLayoutDirection();
        if (eVarN0.g > 1) {
            b bVar = eVarN0.m;
            L l = eVarN0.b;
            androidx.compose.ui.unit.b bVar2 = eVarN0.i;
            Intrinsics.d(bVar2);
            b bVarC = AbstractC3218o0.c(bVar, layoutDirection, l, bVar2, eVarN0.c);
            eVarN0.m = bVarC;
            jA = bVarC.a(eVarN0.g, j2);
        } else {
            jA = j2;
        }
        C0982b c0982b = eVarN0.j;
        if (c0982b == null || (sVar = eVarN0.n) == null || sVar.a() || layoutDirection != eVarN0.o || (!androidx.compose.ui.unit.a.b(jA, eVarN0.p) && (androidx.compose.ui.unit.a.h(jA) != androidx.compose.ui.unit.a.h(eVarN0.p) || androidx.compose.ui.unit.a.g(jA) < c0982b.b() || c0982b.d.c))) {
            C0982b c0982bB = eVarN0.b(jA, layoutDirection);
            eVarN0.p = jA;
            long jI = L5.i(jA, R5.a(AbstractC0484d0.q(c0982bB.d()), AbstractC0484d0.q(c0982bB.b())));
            eVarN0.l = jI;
            eVarN0.k = eVarN0.d != 3 && (((float) ((int) (jI >> 32))) < c0982bB.d() || ((float) ((int) (jI & 4294967295L))) < c0982bB.b());
            eVarN0.j = c0982bB;
            z = true;
        } else {
            if (!androidx.compose.ui.unit.a.b(jA, eVarN0.p)) {
                C0982b c0982b2 = eVarN0.j;
                Intrinsics.d(c0982b2);
                long jI2 = L5.i(jA, R5.a(AbstractC0484d0.q(Math.min(c0982b2.a.i.b(), c0982b2.d())), AbstractC0484d0.q(c0982b2.b())));
                eVarN0.l = jI2;
                eVarN0.k = eVarN0.d != 3 && (((float) ((int) (jI2 >> 32))) < c0982b2.d() || ((float) ((int) (jI2 & 4294967295L))) < c0982b2.b());
                eVarN0.p = jA;
            }
            z = false;
        }
        s sVar2 = eVarN0.n;
        if (sVar2 != null) {
            sVar2.a();
        }
        Unit unit = Unit.a;
        C0982b c0982b3 = eVarN0.j;
        Intrinsics.d(c0982b3);
        long j3 = eVarN0.l;
        if (z) {
            AbstractC0910f.t(this, 2).c1();
            Map linkedHashMap = this.u;
            if (linkedHashMap == null) {
                linkedHashMap = new LinkedHashMap(2);
            }
            C0893n c0893n = AbstractC0882c.a;
            x xVar = c0982b3.d;
            linkedHashMap.put(c0893n, Integer.valueOf(Math.round(xVar.d(0))));
            linkedHashMap.put(AbstractC0882c.b, Integer.valueOf(Math.round(xVar.d(xVar.f - 1))));
            this.u = linkedHashMap;
        }
        int i = (int) (j3 >> 32);
        int i2 = (int) (j3 & 4294967295L);
        int iMin = Math.min(i, 262142);
        int iMin2 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iMin3 = i == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.min(i, 262142);
        int iG = L5.g(iMin3 == Integer.MAX_VALUE ? iMin : iMin3);
        if (i2 != Integer.MAX_VALUE) {
            iMin2 = Math.min(iG, i2);
        }
        W wB = j.B(L5.a(iMin, iMin3, Math.min(iG, i2), iMin2));
        Map map = this.u;
        Intrinsics.d(map);
        return m.n0(i, i2, map, new C(wB, 12));
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(O o, J j, int i) {
        return N0(o).a(i, o.getLayoutDirection());
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(v vVar) {
        o oVar = this.w;
        if (oVar == null) {
            oVar = new o(this, 0);
            this.w = oVar;
        }
        t.j(vVar, new C0995g(6, this.n, null));
        n nVar = this.x;
        if (nVar != null) {
            boolean z = nVar.c;
            u uVar = r.w;
            kotlin.reflect.n[] nVarArr = t.a;
            kotlin.reflect.n nVar2 = nVarArr[15];
            uVar.a(vVar, Boolean.valueOf(z));
            C0995g c0995g = new C0995g(6, nVar.b, null);
            u uVar2 = r.v;
            kotlin.reflect.n nVar3 = nVarArr[14];
            uVar2.a(vVar, c0995g);
        }
        o oVar2 = new o(this, 1);
        u uVar3 = androidx.compose.ui.semantics.j.j;
        androidx.compose.ui.semantics.a aVar = new androidx.compose.ui.semantics.a(null, oVar2);
        androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
        kVar.b(uVar3, aVar);
        kVar.b(androidx.compose.ui.semantics.j.k, new androidx.compose.ui.semantics.a(null, new o(this, 2)));
        kVar.b(androidx.compose.ui.semantics.j.l, new androidx.compose.ui.semantics.a(null, new K(this, 16)));
        t.c(vVar, oVar);
    }
}
