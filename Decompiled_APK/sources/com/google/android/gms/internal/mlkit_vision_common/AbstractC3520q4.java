package com.google.android.gms.internal.mlkit_vision_common;

import com.google.common.base.Predicate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.q4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3520q4 {
    public static void a(List list, Predicate predicate, int i, int i2) {
        for (int size = list.size() - 1; size > i2; size--) {
            if (predicate.apply(list.get(size))) {
                list.remove(size);
            }
        }
        for (int i3 = i2 - 1; i3 >= i; i3--) {
            list.remove(i3);
        }
    }

    public static final ArrayList b(long j, List list, boolean z) {
        boolean z2;
        Intrinsics.checkNotNullParameter(list, "<this>");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.quizlet.learn.checkpoint.data.d dVar = (com.quizlet.learn.checkpoint.data.d) it2.next();
            com.quizlet.studiablemodels.i iVar = dVar.a;
            long j2 = iVar.a;
            if (j2 == j) {
                com.quizlet.studiablemodels.e word = iVar.b;
                Intrinsics.checkNotNullParameter(word, "word");
                com.quizlet.studiablemodels.e definition = iVar.c;
                Intrinsics.checkNotNullParameter(definition, "definition");
                z2 = z;
                com.quizlet.studiablemodels.i termShapedCard = new com.quizlet.studiablemodels.i(j2, word, definition, null, z2);
                Intrinsics.checkNotNullParameter(termShapedCard, "termShapedCard");
                dVar = new com.quizlet.learn.checkpoint.data.d(termShapedCard, dVar.b);
            } else {
                z2 = z;
            }
            arrayList.add(dVar);
            z = z2;
        }
        return arrayList;
    }
}
