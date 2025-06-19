package com.quizlet.features.match.viewmodel;

import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import com.quizlet.features.match.data.AbstractC4353i;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.b0;
import com.quizlet.features.match.data.c0;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class i extends c {
    public Integer k;

    @Override // com.quizlet.features.match.viewmodel.c
    public final Pair D(O6 o6) {
        c0 matchData = (c0) o6;
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        return new Pair((C4345a) ((b0) C()).a.get(matchData.b), (C4345a) ((b0) C()).a.get(matchData.c));
    }

    @Override // com.quizlet.features.match.viewmodel.c
    public final AbstractC4353i F(com.quizlet.features.match.studyengine.g matchGameManager) {
        Intrinsics.checkNotNullParameter(matchGameManager, "matchGameManager");
        ArrayList arrayList = ((com.quizlet.features.match.studyengine.e) matchGameManager).b;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (next instanceof C4345a) {
                arrayList2.add(next);
            }
        }
        return new b0(arrayList2);
    }

    @Override // com.quizlet.features.match.viewmodel.c
    public final void J() {
        this.k = null;
    }
}
