package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.w1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4723t {
    public final ArrayList a;
    public final AbstractC3603d6 b;

    public C4723t(ArrayList studySets, AbstractC3603d6 abstractC3603d6) {
        Intrinsics.checkNotNullParameter(studySets, "studySets");
        this.a = studySets;
        this.b = abstractC3603d6;
    }

    public static ArrayList a(List list, w1 w1Var) {
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBStudySet dBStudySet = (DBStudySet) it2.next();
            arrayList.add(new S(dBStudySet, Long.valueOf(dBStudySet.getSetId()), w1Var, true));
        }
        return CollectionsKt.y0(arrayList);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4723t)) {
            return false;
        }
        C4723t c4723t = (C4723t) obj;
        return this.a.equals(c4723t.a) && Intrinsics.b(this.b, c4723t.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        AbstractC3603d6 abstractC3603d6 = this.b;
        return iHashCode + (abstractC3603d6 == null ? 0 : abstractC3603d6.hashCode());
    }

    public final String toString() {
        return "HomeRecommendedSets(studySets=" + this.a + ", recommendationSource=" + this.b + ")";
    }
}
