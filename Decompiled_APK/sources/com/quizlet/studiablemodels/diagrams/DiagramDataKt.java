package com.quizlet.studiablemodels.diagrams;

import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBTerm;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class DiagramDataKt {
    public static final ArrayList a(List list, List terms) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(terms, "terms");
        ArrayList arrayList = new ArrayList(C.q(terms, 10));
        Iterator it2 = terms.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((DBTerm) it2.next()).getId()));
        }
        ArrayList arrayList2 = new ArrayList();
        for (Object obj : list) {
            if (arrayList.contains(Long.valueOf(((DBDiagramShape) obj).getTermId()))) {
                arrayList2.add(obj);
            }
        }
        return arrayList2;
    }
}
