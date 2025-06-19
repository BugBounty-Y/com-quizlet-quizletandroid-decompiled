package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Y4 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.util.Collection, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.util.ArrayList] */
    public static final boolean a(ArrayList arrayList) {
        ?? arrayList2;
        long j;
        if (arrayList.size() >= 2) {
            if (arrayList.size() == 0 || arrayList.size() == 1) {
                arrayList2 = kotlin.collections.K.a;
            } else {
                arrayList2 = new ArrayList();
                Object obj = arrayList.get(0);
                int i = kotlin.collections.B.i(arrayList);
                int i2 = 0;
                while (i2 < i) {
                    i2++;
                    Object obj2 = arrayList.get(i2);
                    androidx.compose.ui.semantics.o oVar = (androidx.compose.ui.semantics.o) obj2;
                    androidx.compose.ui.semantics.o oVar2 = (androidx.compose.ui.semantics.o) obj;
                    arrayList2.add(new androidx.compose.ui.geometry.b(Q4.c(Math.abs(androidx.compose.ui.geometry.b.d(oVar2.e().c()) - androidx.compose.ui.geometry.b.d(oVar.e().c())), Math.abs(androidx.compose.ui.geometry.b.e(oVar2.e().c()) - androidx.compose.ui.geometry.b.e(oVar.e().c())))));
                    obj = obj2;
                }
            }
            if (arrayList2.size() == 1) {
                j = ((androidx.compose.ui.geometry.b) CollectionsKt.L(arrayList2)).a;
            } else {
                if (arrayList2.isEmpty()) {
                    throw new UnsupportedOperationException("Empty collection can't be reduced.");
                }
                Object objL = CollectionsKt.L(arrayList2);
                int i3 = kotlin.collections.B.i(arrayList2);
                if (1 <= i3) {
                    int i4 = 1;
                    while (true) {
                        objL = new androidx.compose.ui.geometry.b(androidx.compose.ui.geometry.b.h(((androidx.compose.ui.geometry.b) objL).a, ((androidx.compose.ui.geometry.b) arrayList2.get(i4)).a));
                        if (i4 == i3) {
                            break;
                        }
                        i4++;
                    }
                }
                j = ((androidx.compose.ui.geometry.b) objL).a;
            }
            if (androidx.compose.ui.geometry.b.e(j) >= androidx.compose.ui.geometry.b.d(j)) {
                return false;
            }
        }
        return true;
    }

    public static final void b(androidx.core.view.accessibility.e eVar, androidx.compose.ui.semantics.o oVar) {
        Object obj = oVar.i().a.get(androidx.compose.ui.semantics.r.g);
        if (obj == null) {
            obj = null;
        }
        if (obj != null) {
            throw new ClassCastException();
        }
        androidx.compose.ui.semantics.o oVarJ = oVar.j();
        if (oVarJ == null) {
            return;
        }
        Object obj2 = oVarJ.i().a.get(androidx.compose.ui.semantics.r.e);
        if (obj2 == null) {
            obj2 = null;
        }
        if (obj2 != null) {
            Object obj3 = oVarJ.i().a.get(androidx.compose.ui.semantics.r.f);
            androidx.compose.ui.semantics.b bVar = (androidx.compose.ui.semantics.b) (obj3 != null ? obj3 : null);
            if (bVar == null || (bVar.a >= 0 && bVar.b >= 0)) {
                if (oVar.i().a.containsKey(androidx.compose.ui.semantics.r.A)) {
                    ArrayList arrayList = new ArrayList();
                    List listH = androidx.compose.ui.semantics.o.h(oVarJ, 4);
                    int size = listH.size();
                    int i = 0;
                    for (int i2 = 0; i2 < size; i2++) {
                        androidx.compose.ui.semantics.o oVar2 = (androidx.compose.ui.semantics.o) listH.get(i2);
                        if (oVar2.i().a.containsKey(androidx.compose.ui.semantics.r.A)) {
                            arrayList.add(oVar2);
                            if (oVar2.c.t() < oVar.c.t()) {
                                i++;
                            }
                        }
                    }
                    if (arrayList.isEmpty()) {
                        return;
                    }
                    boolean zA = a(arrayList);
                    int i3 = zA ? 0 : i;
                    int i4 = zA ? i : 0;
                    Object obj4 = oVar.i().a.get(androidx.compose.ui.semantics.r.A);
                    if (obj4 == null) {
                        obj4 = Boolean.FALSE;
                    }
                    eVar.k(androidx.webkit.internal.p.r(i3, 1, i4, 1, ((Boolean) obj4).booleanValue()));
                }
            }
        }
    }

    public static final assistantMode.enums.m c(assistantMode.enums.E e) {
        Intrinsics.checkNotNullParameter(e, "<this>");
        int iOrdinal = e.ordinal();
        if (iOrdinal == 1) {
            return assistantMode.enums.m.b;
        }
        if (iOrdinal == 2) {
            return assistantMode.enums.m.c;
        }
        if (iOrdinal == 4) {
            return assistantMode.enums.m.d;
        }
        throw new IllegalArgumentException("No card side equivalent for TermSide: " + e);
    }
}
