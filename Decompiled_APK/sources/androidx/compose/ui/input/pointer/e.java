package androidx.compose.ui.input.pointer;

import androidx.collection.C0219q;
import androidx.collection.G;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.node.l0;
import com.google.android.gms.internal.measurement.C3083y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e extends androidx.webkit.internal.p {
    public final androidx.compose.ui.p c;
    public final androidx.compose.ui.input.pointer.util.b d;
    public final C0219q e;
    public a0 f;
    public f g;
    public boolean h;
    public boolean i;
    public boolean j;

    public e(androidx.compose.ui.p pVar) {
        super(6);
        this.c = pVar;
        androidx.compose.ui.input.pointer.util.b bVar = new androidx.compose.ui.input.pointer.util.b();
        bVar.b = new long[2];
        this.d = bVar;
        this.e = new C0219q(2);
        this.i = true;
        this.j = true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v11 */
    /* JADX WARN: Type inference failed for: r1v12 */
    /* JADX WARN: Type inference failed for: r1v2, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v4 */
    /* JADX WARN: Type inference failed for: r1v5, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v9 */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v11 */
    /* JADX WARN: Type inference failed for: r4v12 */
    /* JADX WARN: Type inference failed for: r4v13 */
    /* JADX WARN: Type inference failed for: r4v14 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v4 */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r4v6, types: [androidx.compose.runtime.collection.b] */
    public final void A() {
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
        int i = bVar.c;
        if (i > 0) {
            Object[] objArr = bVar.a;
            int i2 = 0;
            do {
                ((e) objArr[i2]).A();
                i2++;
            } while (i2 < i);
        }
        AbstractC0918n abstractC0918nF = this.c;
        ?? bVar2 = 0;
        while (abstractC0918nF != 0) {
            if (abstractC0918nF instanceof l0) {
                ((l0) abstractC0918nF).F();
            } else if ((abstractC0918nF.c & 16) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                androidx.compose.ui.p pVar = abstractC0918nF.o;
                int i3 = 0;
                abstractC0918nF = abstractC0918nF;
                bVar2 = bVar2;
                while (pVar != null) {
                    if ((pVar.c & 16) != 0) {
                        i3++;
                        bVar2 = bVar2;
                        if (i3 == 1) {
                            abstractC0918nF = pVar;
                        } else {
                            if (bVar2 == 0) {
                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                            }
                            if (abstractC0918nF != 0) {
                                bVar2.b(abstractC0918nF);
                                abstractC0918nF = 0;
                            }
                            bVar2.b(pVar);
                        }
                    }
                    pVar = pVar.f;
                    abstractC0918nF = abstractC0918nF;
                    bVar2 = bVar2;
                }
                if (i3 == 1) {
                }
            }
            abstractC0918nF = AbstractC0910f.f(bVar2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v3 */
    /* JADX WARN: Type inference failed for: r8v4, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r8v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v6 */
    /* JADX WARN: Type inference failed for: r8v7 */
    /* JADX WARN: Type inference failed for: r8v8 */
    /* JADX WARN: Type inference failed for: r8v9 */
    /* JADX WARN: Type inference failed for: r9v0 */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v10 */
    /* JADX WARN: Type inference failed for: r9v11 */
    /* JADX WARN: Type inference failed for: r9v2 */
    /* JADX WARN: Type inference failed for: r9v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r9v4 */
    /* JADX WARN: Type inference failed for: r9v5 */
    /* JADX WARN: Type inference failed for: r9v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r9v8 */
    /* JADX WARN: Type inference failed for: r9v9 */
    public final boolean B(C3083y1 c3083y1) {
        androidx.compose.runtime.collection.b bVar;
        int i;
        C0219q c0219q = this.e;
        boolean z = false;
        int i2 = 0;
        z = false;
        if (!(c0219q.i() == 0)) {
            androidx.compose.ui.p pVar = this.c;
            if (pVar.m) {
                f fVar = this.g;
                Intrinsics.d(fVar);
                a0 a0Var = this.f;
                Intrinsics.d(a0Var);
                long j = a0Var.c;
                AbstractC0918n abstractC0918nF = pVar;
                ?? bVar2 = 0;
                while (abstractC0918nF != 0) {
                    if (abstractC0918nF instanceof l0) {
                        ((l0) abstractC0918nF).E(fVar, g.c, j);
                    } else if ((abstractC0918nF.c & 16) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                        androidx.compose.ui.p pVar2 = abstractC0918nF.o;
                        int i3 = 0;
                        abstractC0918nF = abstractC0918nF;
                        bVar2 = bVar2;
                        while (pVar2 != null) {
                            if ((pVar2.c & 16) != 0) {
                                i3++;
                                bVar2 = bVar2;
                                if (i3 == 1) {
                                    abstractC0918nF = pVar2;
                                } else {
                                    if (bVar2 == 0) {
                                        bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                    }
                                    if (abstractC0918nF != 0) {
                                        bVar2.b(abstractC0918nF);
                                        abstractC0918nF = 0;
                                    }
                                    bVar2.b(pVar2);
                                }
                            }
                            pVar2 = pVar2.f;
                            abstractC0918nF = abstractC0918nF;
                            bVar2 = bVar2;
                        }
                        if (i3 == 1) {
                        }
                    }
                    abstractC0918nF = AbstractC0910f.f(bVar2);
                }
                if (pVar.m && (i = (bVar = (androidx.compose.runtime.collection.b) this.b).c) > 0) {
                    Object[] objArr = bVar.a;
                    do {
                        ((e) objArr[i2]).B(c3083y1);
                        i2++;
                    } while (i2 < i);
                }
                z = true;
            }
        }
        l(c3083y1);
        c0219q.b();
        this.f = null;
        return z;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v10 */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v13 */
    /* JADX WARN: Type inference failed for: r0v15 */
    /* JADX WARN: Type inference failed for: r0v16 */
    /* JADX WARN: Type inference failed for: r0v4, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r0v5, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r0v9, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r14v10 */
    /* JADX WARN: Type inference failed for: r14v11 */
    /* JADX WARN: Type inference failed for: r14v12 */
    /* JADX WARN: Type inference failed for: r14v13 */
    /* JADX WARN: Type inference failed for: r14v2 */
    /* JADX WARN: Type inference failed for: r14v3 */
    /* JADX WARN: Type inference failed for: r14v4 */
    /* JADX WARN: Type inference failed for: r14v5, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r14v6 */
    /* JADX WARN: Type inference failed for: r14v7 */
    /* JADX WARN: Type inference failed for: r14v8, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r7v0 */
    /* JADX WARN: Type inference failed for: r7v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v12, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v13, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v15 */
    /* JADX WARN: Type inference failed for: r7v16 */
    /* JADX WARN: Type inference failed for: r7v17 */
    /* JADX WARN: Type inference failed for: r7v18 */
    /* JADX WARN: Type inference failed for: r7v19 */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v10, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v12 */
    /* JADX WARN: Type inference failed for: r8v13 */
    /* JADX WARN: Type inference failed for: r8v14 */
    /* JADX WARN: Type inference failed for: r8v15 */
    /* JADX WARN: Type inference failed for: r8v6 */
    /* JADX WARN: Type inference failed for: r8v7, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v8 */
    /* JADX WARN: Type inference failed for: r8v9 */
    public final boolean C(C3083y1 c3083y1, boolean z) {
        androidx.compose.runtime.collection.b bVar;
        int i;
        if (!(this.e.i() == 0)) {
            AbstractC0918n abstractC0918nF = this.c;
            if (abstractC0918nF.m) {
                f fVar = this.g;
                Intrinsics.d(fVar);
                a0 a0Var = this.f;
                Intrinsics.d(a0Var);
                long j = a0Var.c;
                AbstractC0918n abstractC0918nF2 = abstractC0918nF;
                ?? bVar2 = 0;
                while (abstractC0918nF2 != 0) {
                    if (abstractC0918nF2 instanceof l0) {
                        ((l0) abstractC0918nF2).E(fVar, g.a, j);
                    } else if ((abstractC0918nF2.c & 16) != 0 && (abstractC0918nF2 instanceof AbstractC0918n)) {
                        androidx.compose.ui.p pVar = abstractC0918nF2.o;
                        int i2 = 0;
                        abstractC0918nF2 = abstractC0918nF2;
                        bVar2 = bVar2;
                        while (pVar != null) {
                            if ((pVar.c & 16) != 0) {
                                i2++;
                                bVar2 = bVar2;
                                if (i2 == 1) {
                                    abstractC0918nF2 = pVar;
                                } else {
                                    if (bVar2 == 0) {
                                        bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                    }
                                    if (abstractC0918nF2 != 0) {
                                        bVar2.b(abstractC0918nF2);
                                        abstractC0918nF2 = 0;
                                    }
                                    bVar2.b(pVar);
                                }
                            }
                            pVar = pVar.f;
                            abstractC0918nF2 = abstractC0918nF2;
                            bVar2 = bVar2;
                        }
                        if (i2 == 1) {
                        }
                    }
                    abstractC0918nF2 = AbstractC0910f.f(bVar2);
                }
                if (abstractC0918nF.m && (i = (bVar = (androidx.compose.runtime.collection.b) this.b).c) > 0) {
                    Object[] objArr = bVar.a;
                    int i3 = 0;
                    do {
                        e eVar = (e) objArr[i3];
                        Intrinsics.d(this.f);
                        eVar.C(c3083y1, z);
                        i3++;
                    } while (i3 < i);
                }
                if (abstractC0918nF.m) {
                    ?? bVar3 = 0;
                    while (abstractC0918nF != 0) {
                        if (abstractC0918nF instanceof l0) {
                            ((l0) abstractC0918nF).E(fVar, g.b, j);
                        } else if ((abstractC0918nF.c & 16) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                            androidx.compose.ui.p pVar2 = abstractC0918nF.o;
                            int i4 = 0;
                            abstractC0918nF = abstractC0918nF;
                            bVar3 = bVar3;
                            while (pVar2 != null) {
                                if ((pVar2.c & 16) != 0) {
                                    i4++;
                                    bVar3 = bVar3;
                                    if (i4 == 1) {
                                        abstractC0918nF = pVar2;
                                    } else {
                                        if (bVar3 == 0) {
                                            bVar3 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                        }
                                        if (abstractC0918nF != 0) {
                                            bVar3.b(abstractC0918nF);
                                            abstractC0918nF = 0;
                                        }
                                        bVar3.b(pVar2);
                                    }
                                }
                                pVar2 = pVar2.f;
                                abstractC0918nF = abstractC0918nF;
                                bVar3 = bVar3;
                            }
                            if (i4 == 1) {
                            }
                        }
                        abstractC0918nF = AbstractC0910f.f(bVar3);
                    }
                }
                return true;
            }
        }
        return false;
    }

    public final void D(long j, G g) {
        androidx.compose.ui.input.pointer.util.b bVar = this.d;
        int i = 0;
        if (bVar.b(j) && g.d(this) < 0) {
            int i2 = bVar.a;
            int i3 = 0;
            while (true) {
                if (i3 >= i2) {
                    break;
                }
                if (j == bVar.b[i3]) {
                    bVar.c(i3);
                    break;
                }
                i3++;
            }
            this.e.h(j);
        }
        androidx.compose.runtime.collection.b bVar2 = (androidx.compose.runtime.collection.b) this.b;
        int i4 = bVar2.c;
        if (i4 > 0) {
            Object[] objArr = bVar2.a;
            do {
                ((e) objArr[i]).D(j, g);
                i++;
            } while (i < i4);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:126:0x024a  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0137  */
    /* JADX WARN: Type inference failed for: r1v4, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r5v0, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v28 */
    /* JADX WARN: Type inference failed for: r5v29, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v30, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v31 */
    /* JADX WARN: Type inference failed for: r5v32 */
    /* JADX WARN: Type inference failed for: r5v33 */
    /* JADX WARN: Type inference failed for: r5v34 */
    /* JADX WARN: Type inference failed for: r5v35 */
    /* JADX WARN: Type inference failed for: r5v36 */
    /* JADX WARN: Type inference failed for: r5v9, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r6v15 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [int] */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v12, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v14 */
    /* JADX WARN: Type inference failed for: r8v15 */
    /* JADX WARN: Type inference failed for: r8v16 */
    /* JADX WARN: Type inference failed for: r8v17 */
    /* JADX WARN: Type inference failed for: r8v8 */
    /* JADX WARN: Type inference failed for: r8v9, types: [androidx.compose.runtime.collection.b] */
    @Override // androidx.webkit.internal.p
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i(androidx.collection.C0219q r43, androidx.compose.ui.layout.r r44, com.google.android.gms.internal.measurement.C3083y1 r45, boolean r46) {
        /*
            Method dump skipped, instructions count: 591
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.pointer.e.i(androidx.collection.q, androidx.compose.ui.layout.r, com.google.android.gms.internal.measurement.y1, boolean):boolean");
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.webkit.internal.p
    public final void l(C3083y1 c3083y1) {
        super.l(c3083y1);
        f fVar = this.g;
        if (fVar == null) {
            return;
        }
        this.h = this.i;
        ?? r1 = fVar.a;
        int size = r1.size();
        for (int i = 0; i < size; i++) {
            n nVar = (n) r1.get(i);
            boolean z = nVar.d;
            long j = nVar.a;
            boolean zB = c3083y1.b(j);
            boolean z2 = this.i;
            if ((!z && !zB) || (!z && !z2)) {
                androidx.compose.ui.input.pointer.util.b bVar = this.d;
                int i2 = bVar.a;
                int i3 = 0;
                while (true) {
                    if (i3 >= i2) {
                        break;
                    }
                    if (j == bVar.b[i3]) {
                        bVar.c(i3);
                        break;
                    }
                    i3++;
                }
            }
        }
        this.i = false;
        this.j = fVar.d == 5;
    }

    @Override // androidx.webkit.internal.p
    public final String toString() {
        return "Node(pointerInputFilter=" + this.c + ", children=" + ((androidx.compose.runtime.collection.b) this.b) + ", pointerIds=" + this.d + ')';
    }
}
