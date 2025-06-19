package androidx.compose.ui.node;

import android.os.SystemClock;
import android.view.MotionEvent;
import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.lazy.layout.C0432d;
import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.InterfaceC0901w;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_barcode.X4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0907c extends androidx.compose.ui.p implements InterfaceC0926w, InterfaceC0919o, n0, l0, androidx.compose.ui.modifier.e, androidx.compose.ui.modifier.g, j0, InterfaceC0925v, InterfaceC0920p, androidx.compose.ui.focus.d, androidx.compose.ui.focus.n, androidx.compose.ui.focus.q, h0, androidx.compose.ui.draw.b {
    public androidx.compose.ui.o n;
    public androidx.compose.ui.modifier.a o;
    public HashSet p;

    /* JADX WARN: Type inference failed for: r11v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.ui.node.l0
    public final void E(androidx.compose.ui.input.pointer.f fVar, androidx.compose.ui.input.pointer.g gVar, long j) {
        boolean z;
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier");
        C0122z c0122z = ((androidx.compose.ui.input.pointer.r) oVar).e;
        ?? r11 = fVar.a;
        androidx.compose.ui.input.pointer.r rVar = (androidx.compose.ui.input.pointer.r) c0122z.d;
        if (rVar.d) {
            z = true;
            break;
        }
        int size = r11.size();
        for (int i = 0; i < size; i++) {
            androidx.compose.ui.input.pointer.n nVar = (androidx.compose.ui.input.pointer.n) r11.get(i);
            if (androidx.compose.ui.input.pointer.l.a(nVar) || androidx.compose.ui.input.pointer.l.c(nVar)) {
                z = true;
                break;
            }
        }
        z = false;
        int i2 = c0122z.b;
        androidx.compose.ui.input.pointer.g gVar2 = androidx.compose.ui.input.pointer.g.c;
        if (i2 != 3) {
            if (gVar == androidx.compose.ui.input.pointer.g.a && z) {
                c0122z.l(fVar);
            }
            if (gVar == gVar2 && !z) {
                c0122z.l(fVar);
            }
        }
        if (gVar == gVar2) {
            int size2 = r11.size();
            for (int i3 = 0; i3 < size2; i3++) {
                if (!androidx.compose.ui.input.pointer.l.c((androidx.compose.ui.input.pointer.n) r11.get(i3))) {
                    return;
                }
            }
            c0122z.b = 1;
            rVar.d = false;
        }
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        M0(true);
    }

    @Override // androidx.compose.ui.node.l0
    public final void F() {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier");
        C0122z c0122z = ((androidx.compose.ui.input.pointer.r) oVar).e;
        if (c0122z.b == 2) {
            long jUptimeMillis = SystemClock.uptimeMillis();
            androidx.compose.ui.input.pointer.r rVar = (androidx.compose.ui.input.pointer.r) c0122z.d;
            androidx.compose.ui.input.pointer.q qVar = new androidx.compose.ui.input.pointer.q(rVar, 1);
            MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0);
            motionEventObtain.setSource(0);
            qVar.invoke(motionEventObtain);
            motionEventObtain.recycle();
            c0122z.b = 1;
            rVar.d = false;
        }
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        N0();
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void M() {
        AbstractC0910f.n(this);
    }

    public final void M0(boolean z) {
        if (!this.m) {
            W4.f("initializeModifier called on unattached node");
            throw null;
        }
        androidx.compose.ui.o oVar = this.n;
        if ((this.c & 32) != 0) {
            if (oVar instanceof androidx.compose.ui.modifier.c) {
                C0906b c0906b = new C0906b(this, 0);
                androidx.compose.runtime.collection.b bVar = ((C0971v) AbstractC0910f.w(this)).A1;
                if (!bVar.j(c0906b)) {
                    bVar.b(c0906b);
                }
            }
            if (oVar instanceof androidx.compose.ui.modifier.f) {
                androidx.compose.ui.modifier.f fVar = (androidx.compose.ui.modifier.f) oVar;
                androidx.compose.ui.modifier.a aVar = this.o;
                if (aVar == null || !aVar.a(fVar.getKey())) {
                    androidx.compose.ui.modifier.a aVar2 = new androidx.compose.ui.modifier.a();
                    aVar2.b = fVar;
                    this.o = aVar2;
                    if (AbstractC0910f.d(this)) {
                        androidx.compose.ui.modifier.d modifierLocalManager = ((C0971v) AbstractC0910f.w(this)).getModifierLocalManager();
                        androidx.compose.ui.modifier.h key = fVar.getKey();
                        modifierLocalManager.b.b(this);
                        modifierLocalManager.c.b(key);
                        modifierLocalManager.a();
                    }
                } else {
                    aVar.b = fVar;
                    androidx.compose.ui.modifier.d modifierLocalManager2 = ((C0971v) AbstractC0910f.w(this)).getModifierLocalManager();
                    androidx.compose.ui.modifier.h key2 = fVar.getKey();
                    modifierLocalManager2.b.b(this);
                    modifierLocalManager2.c.b(key2);
                    modifierLocalManager2.a();
                }
            }
        }
        if ((this.c & 4) != 0 && !z) {
            AbstractC0910f.t(this, 2).c1();
        }
        if ((this.c & 2) != 0) {
            if (AbstractC0910f.d(this)) {
                a0 a0Var = this.h;
                Intrinsics.d(a0Var);
                ((C0928y) a0Var).u1(this);
                f0 f0Var = a0Var.D;
                if (f0Var != null) {
                    f0Var.invalidate();
                }
            }
            if (!z) {
                AbstractC0910f.t(this, 2).c1();
                AbstractC0910f.v(this).B();
            }
        }
        if (oVar instanceof androidx.compose.foundation.lazy.v) {
            androidx.compose.foundation.lazy.v vVar = (androidx.compose.foundation.lazy.v) oVar;
            E eV = AbstractC0910f.v(this);
            switch (vVar.b) {
                case 0:
                    ((androidx.compose.foundation.lazy.A) vVar.c).k = eV;
                    break;
                case 1:
                    ((androidx.compose.foundation.lazy.grid.A) vVar.c).h = eV;
                    break;
                default:
                    ((L0) ((androidx.compose.foundation.pager.E) vVar.c).x).setValue(eV);
                    break;
            }
        }
        if ((this.c & 256) != 0 && (oVar instanceof C0432d) && AbstractC0910f.d(this)) {
            AbstractC0910f.v(this).B();
        }
        int i = this.c;
        if ((i & 16) != 0 && (oVar instanceof androidx.compose.ui.input.pointer.r)) {
            ((androidx.compose.ui.input.pointer.r) oVar).e.c = this.h;
        }
        if ((i & 8) != 0) {
            ((C0971v) AbstractC0910f.w(this)).y();
        }
    }

    @Override // androidx.compose.ui.node.l0
    public final void N() {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier");
    }

    public final void N0() {
        if (!this.m) {
            W4.f("unInitializeModifier called on unattached node");
            throw null;
        }
        androidx.compose.ui.o oVar = this.n;
        if ((this.c & 32) != 0) {
            if (oVar instanceof androidx.compose.ui.modifier.f) {
                androidx.compose.ui.modifier.d modifierLocalManager = ((C0971v) AbstractC0910f.w(this)).getModifierLocalManager();
                androidx.compose.ui.modifier.h key = ((androidx.compose.ui.modifier.f) oVar).getKey();
                modifierLocalManager.d.b(AbstractC0910f.v(this));
                modifierLocalManager.e.b(key);
                modifierLocalManager.a();
            }
            if (oVar instanceof androidx.compose.ui.modifier.c) {
                ((androidx.compose.ui.modifier.c) oVar).j(AbstractC0910f.a);
            }
        }
        if ((this.c & 8) != 0) {
            ((C0971v) AbstractC0910f.w(this)).y();
        }
    }

    public final void O0() {
        if (this.m) {
            this.p.clear();
            ((C0971v) AbstractC0910f.w(this)).getSnapshotObserver().a(this, C0909e.b, new C0906b(this, 1));
        }
    }

    @Override // androidx.compose.ui.node.j0
    public final Object U(androidx.compose.ui.unit.b bVar, Object obj) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.ParentDataModifier");
        return ((androidx.compose.ui.layout.T) oVar).k();
    }

    @Override // androidx.compose.ui.modifier.e
    public final X4 W() {
        androidx.compose.ui.modifier.a aVar = this.o;
        return aVar != null ? aVar : androidx.compose.ui.modifier.b.b;
    }

    @Override // androidx.compose.ui.draw.b
    public final androidx.compose.ui.unit.b a() {
        return AbstractC0910f.v(this).r;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(O o, androidx.compose.ui.layout.J j, int i) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier");
        return ((InterfaceC0901w) oVar).b(o, j, i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(O o, androidx.compose.ui.layout.J j, int i) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier");
        return ((InterfaceC0901w) oVar).c(o, j, i);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v2, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v16 */
    /* JADX WARN: Type inference failed for: r2v17 */
    /* JADX WARN: Type inference failed for: r2v18 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v11 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v4 */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r4v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v8 */
    /* JADX WARN: Type inference failed for: r4v9 */
    @Override // androidx.compose.ui.modifier.e, androidx.compose.ui.modifier.g
    public final Object d(androidx.compose.ui.modifier.h hVar) {
        V v;
        this.p.add(hVar);
        androidx.compose.ui.p pVar = this.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        androidx.compose.ui.p pVar2 = pVar.e;
        E eV = AbstractC0910f.v(this);
        while (eV != null) {
            if ((((androidx.compose.ui.p) eV.w.f).d & 32) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 32) != 0) {
                        AbstractC0918n abstractC0918nF = pVar2;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof androidx.compose.ui.modifier.e) {
                                androidx.compose.ui.modifier.e eVar = (androidx.compose.ui.modifier.e) abstractC0918nF;
                                if (eVar.W().a(hVar)) {
                                    return eVar.W().b(hVar);
                                }
                            } else if ((abstractC0918nF.c & 32) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar3 = abstractC0918nF.o;
                                int i = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                                while (pVar3 != null) {
                                    if ((pVar3.c & 32) != 0) {
                                        i++;
                                        bVar = bVar;
                                        if (i == 1) {
                                            abstractC0918nF = pVar3;
                                        } else {
                                            if (bVar == 0) {
                                                bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (abstractC0918nF != 0) {
                                                bVar.b(abstractC0918nF);
                                                abstractC0918nF = 0;
                                            }
                                            bVar.b(pVar3);
                                        }
                                    }
                                    pVar3 = pVar3.f;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                }
                                if (i == 1) {
                                }
                            }
                            abstractC0918nF = AbstractC0910f.f(bVar);
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
        return hVar.a.invoke();
    }

    @Override // androidx.compose.ui.focus.d
    public final void d0(androidx.compose.ui.focus.s sVar) {
        W4.f("onFocusEvent called on wrong node");
        throw null;
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(G g) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.draw.DrawModifier");
        ((androidx.compose.ui.draw.f) oVar).e(g);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(O o, androidx.compose.ui.layout.J j, int i) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier");
        return ((InterfaceC0901w) oVar).f(o, j, i);
    }

    @Override // androidx.compose.ui.draw.b
    public final long g() {
        return R5.f(AbstractC0910f.t(this, 128).c);
    }

    @Override // androidx.compose.ui.draw.b
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return AbstractC0910f.v(this).s;
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier");
        return ((InterfaceC0901w) oVar).h(m, j, j2);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(O o, androidx.compose.ui.layout.J j, int i) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier");
        return ((InterfaceC0901w) oVar).i(o, j, i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0925v
    public final void o(long j) {
    }

    @Override // androidx.compose.ui.node.l0
    public final boolean p0() {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier");
        ((androidx.compose.ui.input.pointer.r) oVar).e.getClass();
        return true;
    }

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsModifier");
        androidx.compose.ui.semantics.k kVarM = ((androidx.compose.ui.semantics.l) oVar).m();
        Intrinsics.e(vVar, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsConfiguration");
        androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
        if (kVarM.b) {
            kVar.b = true;
        }
        if (kVarM.c) {
            kVar.c = true;
        }
        for (Map.Entry entry : kVarM.a.entrySet()) {
            androidx.compose.ui.semantics.u uVar = (androidx.compose.ui.semantics.u) entry.getKey();
            Object value = entry.getValue();
            LinkedHashMap linkedHashMap = kVar.a;
            if (!linkedHashMap.containsKey(uVar)) {
                linkedHashMap.put(uVar, value);
            } else if (value instanceof androidx.compose.ui.semantics.a) {
                Object obj = linkedHashMap.get(uVar);
                Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.ui.semantics.AccessibilityAction<*>");
                androidx.compose.ui.semantics.a aVar = (androidx.compose.ui.semantics.a) obj;
                String str = aVar.a;
                if (str == null) {
                    str = ((androidx.compose.ui.semantics.a) value).a;
                }
                InterfaceC4938g interfaceC4938g = aVar.b;
                if (interfaceC4938g == null) {
                    interfaceC4938g = ((androidx.compose.ui.semantics.a) value).b;
                }
                linkedHashMap.put(uVar, new androidx.compose.ui.semantics.a(str, interfaceC4938g));
            }
        }
    }

    public final String toString() {
        return this.n.toString();
    }

    @Override // androidx.compose.ui.node.h0
    public final boolean u() {
        return this.m;
    }

    @Override // androidx.compose.ui.node.InterfaceC0925v
    public final void x(androidx.compose.ui.layout.r rVar) {
    }

    @Override // androidx.compose.ui.node.InterfaceC0920p
    public final void y0(a0 a0Var) {
        androidx.compose.ui.o oVar = this.n;
        Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.layout.OnGloballyPositionedModifier");
        C0432d c0432d = (C0432d) oVar;
        if (c0432d.b) {
            return;
        }
        c0432d.b = true;
        kotlin.coroutines.p pVar = c0432d.c;
        if (pVar != null) {
            kotlin.p pVar2 = kotlin.r.b;
            pVar.resumeWith(Unit.a);
        }
        c0432d.c = null;
    }

    @Override // androidx.compose.ui.focus.n
    public final void z(androidx.compose.ui.focus.k kVar) {
        W4.f("applyFocusProperties called on wrong node");
        throw null;
    }
}
