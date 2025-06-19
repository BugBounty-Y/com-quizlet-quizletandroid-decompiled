package com.quizlet.features.questiontypes.helpers;

import assistantMode.enums.m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3124d5;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.quizlet.features.questiontypes.data.b;
import com.quizlet.features.questiontypes.data.d;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final DiagramData a(StudiableDiagramImage image, List locations) {
        Intrinsics.checkNotNullParameter(image, "image");
        Intrinsics.checkNotNullParameter(locations, "locations");
        DiagramData.Builder builder = new DiagramData.Builder();
        builder.c(AbstractC3124d5.c(image));
        ArrayList arrayList = new ArrayList(C.q(locations, 10));
        Iterator it2 = locations.iterator();
        while (it2.hasNext()) {
            arrayList.add(AbstractC3124d5.b((LocationQuestionSectionData) it2.next()));
        }
        builder.b(arrayList);
        return builder.a();
    }

    public static final N2 b(StudiableQuestion studiableQuestion) {
        com.quizlet.features.infra.models.a aVarF;
        Intrinsics.checkNotNullParameter(studiableQuestion, "<this>");
        StudiableDiagramImage studiableDiagramImage = studiableQuestion.a().e;
        if (studiableQuestion.a().a() && studiableDiagramImage != null) {
            QuestionSectionData questionSectionDataB = studiableQuestion.b();
            Intrinsics.e(questionSectionDataB, "null cannot be cast to non-null type com.quizlet.studiablemodels.LocationQuestionSectionData");
            return new b(a(studiableDiagramImage, A.b((LocationQuestionSectionData) questionSectionDataB)));
        }
        QuestionSectionData questionSectionDataB2 = studiableQuestion.b();
        Intrinsics.e(questionSectionDataB2, "null cannot be cast to non-null type com.quizlet.studiablemodels.DefaultQuestionSectionData");
        DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionDataB2;
        m mVar = studiableQuestion.a().c;
        StudiableImage studiableImage = defaultQuestionSectionData.b;
        StudiableText studiableText = defaultQuestionSectionData.a;
        if (studiableText != null) {
            aVarF = B6.f(studiableText, mVar != m.c && studiableImage == null);
        } else {
            aVarF = null;
        }
        return new d(aVarF, studiableImage);
    }
}
