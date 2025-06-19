package androidx.compose.ui.modifier;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.C0907c;
import androidx.compose.ui.node.E;
import androidx.compose.ui.p;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class d {
    public final C0971v a;
    public final androidx.compose.runtime.collection.b b = new androidx.compose.runtime.collection.b(new C0907c[16]);
    public final androidx.compose.runtime.collection.b c = new androidx.compose.runtime.collection.b(new h[16]);
    public final androidx.compose.runtime.collection.b d = new androidx.compose.runtime.collection.b(new E[16]);
    public final androidx.compose.runtime.collection.b e = new androidx.compose.runtime.collection.b(new h[16]);
    public boolean f;

    public d(C0971v c0971v) {
        this.a = c0971v;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v12 */
    /* JADX WARN: Type inference failed for: r5v13 */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v15 */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v3, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v7 */
    /* JADX WARN: Type inference failed for: r5v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v9, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v10 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r6v9 */
    public static void b(p pVar, h hVar, HashSet hashSet) {
        p pVar2 = pVar.a;
        if (!pVar2.m) {
            W4.f("visitSubtreeIf called on an unattached node");
            throw null;
        }
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new p[16]);
        p pVar3 = pVar2.f;
        if (pVar3 == null) {
            AbstractC0910f.b(bVar, pVar2);
        } else {
            bVar.b(pVar3);
        }
        while (bVar.m()) {
            p pVar4 = (p) bVar.o(bVar.c - 1);
            if ((pVar4.d & 32) != 0) {
                for (p pVar5 = pVar4; pVar5 != null; pVar5 = pVar5.f) {
                    if ((pVar5.c & 32) != 0) {
                        ?? bVar2 = 0;
                        AbstractC0918n abstractC0918nF = pVar5;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof e) {
                                e eVar = (e) abstractC0918nF;
                                if (eVar instanceof C0907c) {
                                    C0907c c0907c = (C0907c) eVar;
                                    if ((c0907c.n instanceof c) && c0907c.p.contains(hVar)) {
                                        hashSet.add(eVar);
                                    }
                                }
                                if (eVar.W().a(hVar)) {
                                    break;
                                }
                            } else if ((abstractC0918nF.c & 32) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                p pVar6 = abstractC0918nF.o;
                                int i = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar2 = bVar2;
                                while (pVar6 != null) {
                                    if ((pVar6.c & 32) != 0) {
                                        i++;
                                        bVar2 = bVar2;
                                        if (i == 1) {
                                            abstractC0918nF = pVar6;
                                        } else {
                                            if (bVar2 == 0) {
                                                bVar2 = new androidx.compose.runtime.collection.b(new p[16]);
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

    public final void a() {
        if (this.f) {
            return;
        }
        this.f = true;
        androidx.compose.ui.input.nestedscroll.b bVar = new androidx.compose.ui.input.nestedscroll.b(this, 3);
        androidx.compose.runtime.collection.b bVar2 = this.a.A1;
        if (bVar2.j(bVar)) {
            return;
        }
        bVar2.b(bVar);
    }
}
