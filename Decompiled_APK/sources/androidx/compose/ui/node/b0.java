package androidx.compose.ui.node;

import androidx.compose.foundation.lazy.layout.C0432d;
import androidx.compose.ui.layout.InterfaceC0901w;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;

/* loaded from: classes.dex */
public abstract class b0 {
    public static final androidx.collection.C a;

    static {
        androidx.collection.C c = androidx.collection.O.a;
        a = new androidx.collection.C();
    }

    public static final void a(androidx.compose.ui.p pVar) {
        if (pVar.m) {
            b(pVar, -1, 1);
        } else {
            W4.f("autoInvalidateInsertedNode called on unattached node");
            throw null;
        }
    }

    public static final void b(androidx.compose.ui.p pVar, int i, int i2) {
        if (!(pVar instanceof AbstractC0918n)) {
            c(pVar, i & pVar.c, i2);
            return;
        }
        AbstractC0918n abstractC0918n = (AbstractC0918n) pVar;
        c(pVar, abstractC0918n.n & i, i2);
        int i3 = (~abstractC0918n.n) & i;
        for (androidx.compose.ui.p pVar2 = abstractC0918n.o; pVar2 != null; pVar2 = pVar2.f) {
            b(pVar2, i3, i2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void c(androidx.compose.ui.p pVar, int i, int i2) {
        if (i2 != 0 || pVar.B0()) {
            if ((i & 2) != 0 && (pVar instanceof InterfaceC0926w)) {
                AbstractC0910f.o((InterfaceC0926w) pVar);
                if (i2 == 2) {
                    a0 a0VarT = AbstractC0910f.t(pVar, 2);
                    a0VarT.o = true;
                    a0VarT.B.invoke();
                    if (a0VarT.D != null) {
                        if (a0VarT.E != null) {
                            a0VarT.E = null;
                        }
                        a0VarT.r1(null, false);
                        a0VarT.l.S(false);
                    }
                }
            }
            if ((i & 128) != 0 && (pVar instanceof InterfaceC0925v) && i2 != 2) {
                AbstractC0910f.v(pVar).B();
            }
            if ((i & 256) != 0 && (pVar instanceof InterfaceC0920p) && i2 != 2) {
                E eV = AbstractC0910f.v(pVar);
                L l = eV.x;
                if (!l.e && !l.d && !eV.F) {
                    C0971v c0971v = (C0971v) H.a(eV);
                    ((androidx.compose.runtime.collection.b) c0971v.H.e.b).b(eV);
                    eV.F = true;
                    c0971v.B(null);
                }
            }
            if ((i & 4) != 0 && (pVar instanceof InterfaceC0919o)) {
                AbstractC0910f.n((InterfaceC0919o) pVar);
            }
            if ((i & 8) != 0 && (pVar instanceof n0)) {
                AbstractC0910f.p((n0) pVar);
            }
            if ((i & 64) != 0 && (pVar instanceof j0)) {
                L l2 = AbstractC0910f.v((j0) pVar).x;
                l2.r.q = true;
                J j = l2.s;
                if (j != null) {
                    j.v = true;
                }
            }
            if ((i & 1024) != 0 && (pVar instanceof androidx.compose.ui.focus.t) && i2 != 2) {
                androidx.compose.ui.focus.a.s((androidx.compose.ui.focus.t) pVar);
            }
            if ((i & 2048) != 0 && (pVar instanceof androidx.compose.ui.focus.n)) {
                androidx.compose.ui.focus.n nVar = (androidx.compose.ui.focus.n) pVar;
                C0911g.b = null;
                nVar.z(C0911g.a);
                if (C0911g.b != null) {
                    if (i2 == 2) {
                        androidx.compose.ui.p pVar2 = ((androidx.compose.ui.p) nVar).a;
                        if (!pVar2.m) {
                            throw new IllegalStateException("visitChildren called on an unattached node");
                        }
                        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                        androidx.compose.ui.p pVar3 = pVar2.f;
                        if (pVar3 == null) {
                            AbstractC0910f.b(bVar, pVar2);
                        } else {
                            bVar.b(pVar3);
                        }
                        while (bVar.m()) {
                            androidx.compose.ui.p pVarF = (androidx.compose.ui.p) bVar.o(bVar.c - 1);
                            if ((pVarF.d & 1024) == 0) {
                                AbstractC0910f.b(bVar, pVarF);
                            } else {
                                while (true) {
                                    if (pVarF == null) {
                                        break;
                                    }
                                    if ((pVarF.c & 1024) != 0) {
                                        androidx.compose.runtime.collection.b bVar2 = null;
                                        while (pVarF != null) {
                                            if (pVarF instanceof androidx.compose.ui.focus.t) {
                                                androidx.compose.ui.focus.a.s((androidx.compose.ui.focus.t) pVarF);
                                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                                int i3 = 0;
                                                for (androidx.compose.ui.p pVar4 = ((AbstractC0918n) pVarF).o; pVar4 != null; pVar4 = pVar4.f) {
                                                    if ((pVar4.c & 1024) != 0) {
                                                        i3++;
                                                        if (i3 == 1) {
                                                            pVarF = pVar4;
                                                        } else {
                                                            if (bVar2 == null) {
                                                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                            }
                                                            if (pVarF != null) {
                                                                bVar2.b(pVarF);
                                                                pVarF = null;
                                                            }
                                                            bVar2.b(pVar4);
                                                        }
                                                    }
                                                }
                                                if (i3 == 1) {
                                                }
                                            }
                                            pVarF = AbstractC0910f.f(bVar2);
                                        }
                                    } else {
                                        pVarF = pVarF.f;
                                    }
                                }
                            }
                        }
                    } else {
                        androidx.compose.ui.focus.f fVar = ((androidx.compose.ui.focus.j) ((C0971v) AbstractC0910f.w(nVar)).getFocusOwner()).g;
                        fVar.b(fVar.e, nVar);
                    }
                }
            }
            if ((i & 4096) == 0 || !(pVar instanceof androidx.compose.ui.focus.d)) {
                return;
            }
            androidx.compose.ui.focus.d dVar = (androidx.compose.ui.focus.d) pVar;
            androidx.compose.ui.focus.f fVar2 = ((androidx.compose.ui.focus.j) ((C0971v) AbstractC0910f.w(dVar)).getFocusOwner()).g;
            fVar2.b(fVar2.d, dVar);
        }
    }

    public static final void d(androidx.compose.ui.p pVar) {
        if (pVar.m) {
            b(pVar, -1, 0);
        } else {
            W4.f("autoInvalidateUpdatedNode called on unattached node");
            throw null;
        }
    }

    public static final int e(androidx.compose.ui.o oVar) {
        int i = oVar instanceof InterfaceC0901w ? 3 : 1;
        if (oVar instanceof androidx.compose.ui.draw.f) {
            i |= 4;
        }
        if (oVar instanceof androidx.compose.ui.semantics.l) {
            i |= 8;
        }
        if (oVar instanceof androidx.compose.ui.input.pointer.r) {
            i |= 16;
        }
        if ((oVar instanceof androidx.compose.ui.modifier.c) || (oVar instanceof androidx.compose.ui.modifier.f)) {
            i |= 32;
        }
        if (oVar instanceof C0432d) {
            i |= 256;
        }
        return oVar instanceof androidx.compose.ui.layout.T ? i | 64 : i;
    }

    public static final int f(androidx.compose.ui.p pVar) {
        int i = pVar.c;
        if (i != 0) {
            return i;
        }
        Class<?> cls = pVar.getClass();
        androidx.collection.C c = a;
        int iC = c.c(cls);
        if (iC >= 0) {
            return c.c[iC];
        }
        int i2 = pVar instanceof InterfaceC0926w ? 3 : 1;
        if (pVar instanceof InterfaceC0919o) {
            i2 |= 4;
        }
        if (pVar instanceof n0) {
            i2 |= 8;
        }
        if (pVar instanceof l0) {
            i2 |= 16;
        }
        if (pVar instanceof androidx.compose.ui.modifier.e) {
            i2 |= 32;
        }
        if (pVar instanceof j0) {
            i2 |= 64;
        }
        if (pVar instanceof InterfaceC0925v) {
            i2 |= 128;
        }
        if (pVar instanceof InterfaceC0920p) {
            i2 |= 256;
        }
        if (pVar instanceof androidx.compose.ui.focus.t) {
            i2 |= 1024;
        }
        if (pVar instanceof androidx.compose.ui.focus.n) {
            i2 |= 2048;
        }
        if (pVar instanceof androidx.compose.ui.focus.d) {
            i2 |= 4096;
        }
        if (pVar instanceof androidx.compose.ui.input.key.d) {
            i2 |= 8192;
        }
        if (pVar instanceof androidx.compose.ui.input.rotary.b) {
            i2 |= 16384;
        }
        if (pVar instanceof InterfaceC0916l) {
            i2 |= 32768;
        }
        if (pVar instanceof q0) {
            i2 |= 262144;
        }
        c.g(i2, cls);
        return i2;
    }

    public static final int g(androidx.compose.ui.p pVar) {
        if (!(pVar instanceof AbstractC0918n)) {
            return f(pVar);
        }
        AbstractC0918n abstractC0918n = (AbstractC0918n) pVar;
        int iG = abstractC0918n.n;
        for (androidx.compose.ui.p pVar2 = abstractC0918n.o; pVar2 != null; pVar2 = pVar2.f) {
            iG |= g(pVar2);
        }
        return iG;
    }

    public static final boolean h(int i) {
        return (i & 128) != 0;
    }
}
