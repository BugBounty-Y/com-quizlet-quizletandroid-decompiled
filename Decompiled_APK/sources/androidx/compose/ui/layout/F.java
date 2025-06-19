package androidx.compose.ui.layout;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.p0;
import androidx.compose.ui.node.q0;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;

/* loaded from: classes.dex */
public final class F implements c0 {
    public final /* synthetic */ G a;
    public final /* synthetic */ Object b;

    public F(G g, Object obj) {
        this.a = g;
        this.b = obj;
    }

    @Override // androidx.compose.ui.layout.c0
    public final int a() {
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) this.a.j.get(this.b);
        if (e != null) {
            return ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.n()).b).c;
        }
        return 0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v0, types: [androidx.compose.foundation.layout.Y] */
    /* JADX WARN: Type inference failed for: r7v10, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v12 */
    /* JADX WARN: Type inference failed for: r7v13 */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v15 */
    /* JADX WARN: Type inference failed for: r7v16 */
    /* JADX WARN: Type inference failed for: r7v2 */
    /* JADX WARN: Type inference failed for: r7v3, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v8 */
    /* JADX WARN: Type inference failed for: r7v9, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v4 */
    /* JADX WARN: Type inference failed for: r8v5 */
    /* JADX WARN: Type inference failed for: r8v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r8v8 */
    /* JADX WARN: Type inference failed for: r8v9 */
    @Override // androidx.compose.ui.layout.c0
    public final void b(androidx.compose.foundation.layout.Y y) {
        androidx.compose.ui.node.V v;
        androidx.compose.ui.p pVar;
        p0 p0Var;
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) this.a.j.get(this.b);
        if (e == null || (v = e.w) == null || (pVar = (androidx.compose.ui.p) v.f) == null) {
            return;
        }
        androidx.compose.ui.p pVar2 = pVar.a;
        if (!pVar2.m) {
            W4.f("visitSubtreeIf called on an unattached node");
            throw null;
        }
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar3 = pVar2.f;
        if (pVar3 == null) {
            AbstractC0910f.b(bVar, pVar2);
        } else {
            bVar.b(pVar3);
        }
        while (bVar.m()) {
            androidx.compose.ui.p pVar4 = (androidx.compose.ui.p) bVar.o(bVar.c - 1);
            if ((pVar4.d & 262144) != 0) {
                for (androidx.compose.ui.p pVar5 = pVar4; pVar5 != null; pVar5 = pVar5.f) {
                    if ((pVar5.c & 262144) != 0) {
                        ?? bVar2 = 0;
                        AbstractC0918n abstractC0918nF = pVar5;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof q0) {
                                q0 q0Var = (q0) abstractC0918nF;
                                boolean zEquals = "androidx.compose.foundation.lazy.layout.TraversablePrefetchStateNode".equals(q0Var.m());
                                p0 p0Var2 = p0.b;
                                if (zEquals) {
                                    y.invoke(q0Var);
                                    p0Var = p0Var2;
                                } else {
                                    p0Var = p0.a;
                                }
                                if (p0Var == p0.c) {
                                    return;
                                }
                                if (p0Var == p0Var2) {
                                    break;
                                }
                            } else if ((abstractC0918nF.c & 262144) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar6 = abstractC0918nF.o;
                                int i = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar2 = bVar2;
                                while (pVar6 != null) {
                                    if ((pVar6.c & 262144) != 0) {
                                        i++;
                                        bVar2 = bVar2;
                                        if (i == 1) {
                                            abstractC0918nF = pVar6;
                                        } else {
                                            if (bVar2 == 0) {
                                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (abstractC0918nF != 0) {
                                                bVar2.b(abstractC0918nF);
                                                abstractC0918nF = 0;
                                            }
                                            bVar2.b(pVar6);
                                        }
                                    }
                                    pVar6 = pVar6.f;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar2 = bVar2;
                                }
                                if (i == 1) {
                                }
                            }
                            abstractC0918nF = AbstractC0910f.f(bVar2);
                        }
                    }
                }
            }
            AbstractC0910f.b(bVar, pVar4);
        }
    }

    @Override // androidx.compose.ui.layout.c0
    public final void c(int i, long j) {
        G g = this.a;
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) g.j.get(this.b);
        if (e == null || !e.E()) {
            return;
        }
        int i2 = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.n()).b).c;
        if (i < 0 || i >= i2) {
            throw new IndexOutOfBoundsException("Index (" + i + ") is out of bound of [0, " + i2 + ')');
        }
        if (e.F()) {
            throw new IllegalArgumentException("Pre-measure called on node that is not placed");
        }
        androidx.compose.ui.node.E e2 = g.a;
        e2.l = true;
        ((C0971v) androidx.compose.ui.node.H.a(e)).r((androidx.compose.ui.node.E) ((androidx.collection.E) e.n()).get(i), j);
        e2.l = false;
    }

    @Override // androidx.compose.ui.layout.c0
    public final void dispose() {
        G g = this.a;
        g.e();
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) g.j.remove(this.b);
        if (e != null) {
            if (g.o <= 0) {
                throw new IllegalStateException("No pre-composed items to dispose");
            }
            androidx.compose.ui.node.E e2 = g.a;
            int iK = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e2.p()).b).k(e);
            int i = ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e2.p()).b).c;
            int i2 = g.o;
            if (iK < i - i2) {
                throw new IllegalStateException("Item is not in pre-composed item range");
            }
            g.n++;
            g.o = i2 - 1;
            int i3 = (((androidx.compose.runtime.collection.b) ((androidx.collection.E) e2.p()).b).c - g.o) - g.n;
            e2.l = true;
            e2.I(iK, i3, 1);
            e2.l = false;
            g.c(i3);
        }
    }
}
