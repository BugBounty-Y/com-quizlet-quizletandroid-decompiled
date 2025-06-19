package androidx.compose.ui.focus;

import androidx.collection.I;
import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.node.V;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.node.c0;
import androidx.compose.ui.node.o0;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class t extends androidx.compose.ui.p implements InterfaceC0916l, c0, androidx.compose.ui.modifier.e {
    public boolean n;
    public boolean o;
    public s p;

    public static final boolean O0(t tVar) {
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            W4.f("visitSubtreeIf called on an unattached node");
            throw null;
        }
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 == null) {
            AbstractC0910f.b(bVar, pVar);
        } else {
            bVar.b(pVar2);
        }
        while (true) {
            if (!bVar.m()) {
                break;
            }
            androidx.compose.ui.p pVar3 = (androidx.compose.ui.p) bVar.o(bVar.c - 1);
            if ((pVar3.d & 1024) != 0) {
                for (androidx.compose.ui.p pVar4 = pVar3; pVar4 != null; pVar4 = pVar4.f) {
                    if ((pVar4.c & 1024) != 0) {
                        androidx.compose.runtime.collection.b bVar2 = null;
                        androidx.compose.ui.p pVarF = pVar4;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                t tVar2 = (t) pVarF;
                                if (tVar2.p != null) {
                                    int iOrdinal = tVar2.N0().ordinal();
                                    if (iOrdinal == 0 || iOrdinal == 1 || iOrdinal == 2) {
                                        return true;
                                    }
                                    if (iOrdinal != 3) {
                                        throw new NoWhenBranchMatchedException();
                                    }
                                }
                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i = 0;
                                for (androidx.compose.ui.p pVar5 = ((AbstractC0918n) pVarF).o; pVar5 != null; pVar5 = pVar5.f) {
                                    if ((pVar5.c & 1024) != 0) {
                                        i++;
                                        if (i == 1) {
                                            pVarF = pVar5;
                                        } else {
                                            if (bVar2 == null) {
                                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar2.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar2.b(pVar5);
                                        }
                                    }
                                }
                                if (i == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar2);
                        }
                    }
                }
            }
            AbstractC0910f.b(bVar, pVar3);
        }
        return false;
    }

    public static final boolean P0(t tVar) {
        V v;
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        androidx.compose.ui.p pVar2 = pVar.e;
        E eV = AbstractC0910f.v(tVar);
        while (true) {
            if (eV == null) {
                break;
            }
            if ((((androidx.compose.ui.p) eV.w.f).d & 1024) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 1024) != 0) {
                        androidx.compose.ui.p pVarF = pVar2;
                        androidx.compose.runtime.collection.b bVar = null;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                t tVar2 = (t) pVarF;
                                if (tVar2.p != null) {
                                    int iOrdinal = tVar2.N0().ordinal();
                                    if (iOrdinal != 0) {
                                        if (iOrdinal == 1) {
                                            return true;
                                        }
                                        if (iOrdinal != 2 && iOrdinal != 3) {
                                            throw new NoWhenBranchMatchedException();
                                        }
                                    }
                                }
                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i = 0;
                                for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                    if ((pVar3.c & 1024) != 0) {
                                        i++;
                                        if (i == 1) {
                                            pVarF = pVar3;
                                        } else {
                                            if (bVar == null) {
                                                bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar.b(pVar3);
                                        }
                                    }
                                }
                                if (i == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar);
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
        return false;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0030  */
    @Override // androidx.compose.ui.p
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void F0() {
        /*
            r4 = this;
            androidx.compose.ui.focus.s r0 = r4.N0()
            int r0 = r0.ordinal()
            r1 = 1
            if (r0 == 0) goto L30
            if (r0 == r1) goto L11
            r2 = 2
            if (r0 == r2) goto L30
            goto L45
        L11:
            com.bumptech.glide.manager.p r0 = androidx.compose.ui.focus.a.I(r4)
            boolean r2 = r0.a     // Catch: java.lang.Throwable -> L1d
            if (r2 == 0) goto L1f
            com.bumptech.glide.manager.p.a(r0)     // Catch: java.lang.Throwable -> L1d
            goto L1f
        L1d:
            r1 = move-exception
            goto L2c
        L1f:
            r0.a = r1     // Catch: java.lang.Throwable -> L1d
            androidx.compose.ui.focus.s r1 = androidx.compose.ui.focus.s.c     // Catch: java.lang.Throwable -> L1d
            r4.R0(r1)     // Catch: java.lang.Throwable -> L1d
            kotlin.Unit r1 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L1d
            com.bumptech.glide.manager.p.d(r0)
            goto L45
        L2c:
            com.bumptech.glide.manager.p.d(r0)
            throw r1
        L30:
            androidx.compose.ui.node.g0 r0 = androidx.compose.ui.node.AbstractC0910f.w(r4)
            androidx.compose.ui.platform.v r0 = (androidx.compose.ui.platform.C0971v) r0
            androidx.compose.ui.focus.h r0 = r0.getFocusOwner()
            androidx.compose.ui.focus.j r0 = (androidx.compose.ui.focus.j) r0
            r2 = 0
            r3 = 8
            r0.b(r3, r1, r2)
            androidx.compose.ui.focus.a.s(r4)
        L45:
            r0 = 0
            r4.p = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.t.F0():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v13 */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v15 */
    /* JADX WARN: Type inference failed for: r5v16 */
    /* JADX WARN: Type inference failed for: r5v17 */
    /* JADX WARN: Type inference failed for: r5v18 */
    /* JADX WARN: Type inference failed for: r5v7 */
    /* JADX WARN: Type inference failed for: r5v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v1 */
    /* JADX WARN: Type inference failed for: r7v10 */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v12 */
    /* JADX WARN: Type inference failed for: r7v13 */
    /* JADX WARN: Type inference failed for: r7v2 */
    /* JADX WARN: Type inference failed for: r7v3 */
    /* JADX WARN: Type inference failed for: r7v4, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r7v5 */
    /* JADX WARN: Type inference failed for: r7v6 */
    /* JADX WARN: Type inference failed for: r7v7, types: [androidx.compose.runtime.collection.b] */
    public final l M0() {
        V v;
        l lVar = new l();
        lVar.a = true;
        p pVar = p.b;
        lVar.b = pVar;
        lVar.c = pVar;
        lVar.d = pVar;
        lVar.e = pVar;
        lVar.f = pVar;
        lVar.g = pVar;
        lVar.h = pVar;
        lVar.i = pVar;
        lVar.j = i.c;
        lVar.k = i.d;
        androidx.compose.ui.p pVar2 = this.a;
        if (!pVar2.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        E eV = AbstractC0910f.v(this);
        androidx.compose.ui.p pVar3 = pVar2;
        loop0: while (eV != null) {
            if ((((androidx.compose.ui.p) eV.w.f).d & 3072) != 0) {
                while (pVar3 != null) {
                    int i = pVar3.c;
                    if ((i & 3072) != 0) {
                        if (pVar3 != pVar2 && (i & 1024) != 0) {
                            break loop0;
                        }
                        if ((i & 2048) != 0) {
                            AbstractC0918n abstractC0918nF = pVar3;
                            ?? bVar = 0;
                            while (abstractC0918nF != 0) {
                                if (abstractC0918nF instanceof n) {
                                    ((n) abstractC0918nF).z(lVar);
                                } else if ((abstractC0918nF.c & 2048) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                    androidx.compose.ui.p pVar4 = abstractC0918nF.o;
                                    int i2 = 0;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                    while (pVar4 != null) {
                                        if ((pVar4.c & 2048) != 0) {
                                            i2++;
                                            bVar = bVar;
                                            if (i2 == 1) {
                                                abstractC0918nF = pVar4;
                                            } else {
                                                if (bVar == 0) {
                                                    bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (abstractC0918nF != 0) {
                                                    bVar.b(abstractC0918nF);
                                                    abstractC0918nF = 0;
                                                }
                                                bVar.b(pVar4);
                                            }
                                        }
                                        pVar4 = pVar4.f;
                                        abstractC0918nF = abstractC0918nF;
                                        bVar = bVar;
                                    }
                                    if (i2 == 1) {
                                    }
                                }
                                abstractC0918nF = AbstractC0910f.f(bVar);
                            }
                        }
                    }
                    pVar3 = pVar3.e;
                }
            }
            eV = eV.s();
            pVar3 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
        return lVar;
    }

    public final s N0() {
        s sVar;
        E e;
        C0971v c0971v;
        h focusOwner;
        a0 a0Var = this.a.h;
        com.bumptech.glide.manager.p pVar = (a0Var == null || (e = a0Var.l) == null || (c0971v = e.i) == null || (focusOwner = c0971v.getFocusOwner()) == null) ? null : ((j) focusOwner).h;
        if (pVar != null && (sVar = (s) ((I) pVar.b).f(this)) != null) {
            return sVar;
        }
        s sVar2 = this.p;
        return sVar2 == null ? s.c : sVar2;
    }

    public final void Q0() {
        s sVar = this.p;
        if (sVar == null) {
            if (sVar != null) {
                throw new IllegalStateException("Re-initializing focus target node.");
            }
            com.bumptech.glide.manager.p pVarI = a.I(this);
            try {
                if (pVarI.a) {
                    com.bumptech.glide.manager.p.a(pVarI);
                }
                pVarI.a = true;
                R0((P0(this) && O0(this)) ? s.b : s.c);
                Unit unit = Unit.a;
                com.bumptech.glide.manager.p.d(pVarI);
            } catch (Throwable th) {
                com.bumptech.glide.manager.p.d(pVarI);
                throw th;
            }
        }
        int iOrdinal = N0().ordinal();
        if (iOrdinal == 0 || iOrdinal == 2) {
            J j = new J();
            AbstractC0910f.s(this, new C0242g(19, j, this));
            Object obj = j.a;
            if (obj == null) {
                Intrinsics.m("focusProperties");
                throw null;
            }
            if (((k) obj).b()) {
                return;
            }
            ((j) ((C0971v) AbstractC0910f.w(this)).getFocusOwner()).b(8, true, true);
        }
    }

    public final void R0(s sVar) {
        ((I) a.I(this).b).j(this, sVar);
    }

    @Override // androidx.compose.ui.node.c0
    public final void k0() {
        s sVarN0 = N0();
        Q0();
        if (sVarN0 != N0()) {
            a.E(this);
        }
    }
}
