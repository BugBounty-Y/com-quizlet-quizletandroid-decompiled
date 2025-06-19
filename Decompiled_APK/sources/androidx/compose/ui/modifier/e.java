package androidx.compose.ui.modifier;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.V;
import androidx.compose.ui.node.o0;
import androidx.compose.ui.p;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_barcode.X4;

/* loaded from: classes.dex */
public interface e extends g, InterfaceC0917m {
    default X4 W() {
        return b.b;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v3, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r3v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v13 */
    /* JADX WARN: Type inference failed for: r3v14 */
    /* JADX WARN: Type inference failed for: r3v15 */
    /* JADX WARN: Type inference failed for: r3v16 */
    /* JADX WARN: Type inference failed for: r3v17 */
    /* JADX WARN: Type inference failed for: r3v18 */
    /* JADX WARN: Type inference failed for: r3v7 */
    /* JADX WARN: Type inference failed for: r3v8, types: [androidx.compose.ui.p] */
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
    /* JADX WARN: Type inference failed for: r9v0, types: [androidx.compose.ui.modifier.e, androidx.compose.ui.node.m] */
    @Override // androidx.compose.ui.modifier.g
    default Object d(h hVar) {
        V v;
        p pVar = ((p) this).a;
        boolean z = pVar.m;
        if (!z) {
            W4.e("ModifierLocal accessed from an unattached node");
            throw null;
        }
        if (!z) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        p pVar2 = pVar.e;
        E eV = AbstractC0910f.v(this);
        while (eV != null) {
            if ((((p) eV.w.f).d & 32) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 32) != 0) {
                        AbstractC0918n abstractC0918nF = pVar2;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof e) {
                                e eVar = (e) abstractC0918nF;
                                if (eVar.W().a(hVar)) {
                                    return eVar.W().b(hVar);
                                }
                            } else if ((abstractC0918nF.c & 32) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                p pVar3 = abstractC0918nF.o;
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
                                                bVar = new androidx.compose.runtime.collection.b(new p[16]);
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
}
