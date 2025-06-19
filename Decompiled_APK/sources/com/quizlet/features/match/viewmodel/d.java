package com.quizlet.features.match.viewmodel;

import androidx.lifecycle.m0;
import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import com.quizlet.features.match.data.AbstractC4353i;
import com.quizlet.features.match.data.AbstractC4355k;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4346b;
import com.quizlet.features.match.data.C4347c;
import com.quizlet.features.match.data.C4349e;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class d extends c {
    public Integer k;
    public Long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(m0 savedStateHandle, com.quizlet.features.match.studyengine.f matchGameManagerFactory, com.quizlet.data.repository.course.membership.c matchStudyModeLoggerFactory) {
        super(matchGameManagerFactory.a(savedStateHandle), matchStudyModeLoggerFactory.f(savedStateHandle));
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(matchGameManagerFactory, "matchGameManagerFactory");
        Intrinsics.checkNotNullParameter(matchStudyModeLoggerFactory, "matchStudyModeLoggerFactory");
    }

    @Override // com.quizlet.features.match.viewmodel.c
    public final Pair D(O6 o6) {
        C4347c matchData = (C4347c) o6;
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        Iterator it2 = ((C4346b) C()).b.iterator();
        while (it2.hasNext()) {
            C4349e c4349e = (C4349e) it2.next();
            if (c4349e.b == matchData.b) {
                return new Pair(c4349e, (C4345a) ((C4346b) C()).c.get(matchData.c));
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    @Override // com.quizlet.features.match.viewmodel.c
    public final AbstractC4353i F(com.quizlet.features.match.studyengine.g matchGameManager) {
        Intrinsics.checkNotNullParameter(matchGameManager, "matchGameManager");
        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) matchGameManager;
        DiagramData diagramData = eVar.c;
        if (diagramData == null) {
            throw new IllegalArgumentException("Diagram match games require a valid DiagramData");
        }
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = eVar.b.iterator();
        while (it2.hasNext()) {
            AbstractC4355k abstractC4355k = (AbstractC4355k) it2.next();
            if (abstractC4355k instanceof C4345a) {
                arrayList.add(abstractC4355k);
            } else {
                if (!(abstractC4355k instanceof C4349e)) {
                    throw new NoWhenBranchMatchedException();
                }
                arrayList2.add(abstractC4355k);
            }
        }
        return new C4346b(diagramData, arrayList2, arrayList);
    }

    @Override // com.quizlet.features.match.viewmodel.c
    public final void J() {
        this.l = null;
        this.k = null;
    }
}
