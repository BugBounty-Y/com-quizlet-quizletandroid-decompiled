package com.quizlet.features.infra.basestudy.helper;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3124d5;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.quizlet.features.infra.models.flashcards.g;
import com.quizlet.features.infra.models.flashcards.j;
import com.quizlet.features.infra.models.flashcards.k;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public abstract class a {
    public static final D6 a(QuestionSectionData questionSectionData, StudiableDiagramImage studiableDiagramImage) {
        Intrinsics.checkNotNullParameter(questionSectionData, "<this>");
        if (!(questionSectionData instanceof DefaultQuestionSectionData)) {
            if (!(questionSectionData instanceof LocationQuestionSectionData)) {
                throw new NoWhenBranchMatchedException();
            }
            LocationQuestionSectionData locationQuestionSectionData = (LocationQuestionSectionData) questionSectionData;
            if (studiableDiagramImage == null) {
                throw new IllegalStateException("LocationQuestionSectionData must not have null StudiableDiagramImage");
            }
            DiagramData.Builder builder = new DiagramData.Builder();
            builder.c(AbstractC3124d5.c(studiableDiagramImage));
            builder.b(A.b(AbstractC3124d5.b(locationQuestionSectionData)));
            return new com.quizlet.features.infra.models.flashcards.b(builder.a());
        }
        DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData;
        StudiableText studiableText = defaultQuestionSectionData.a;
        StudiableImage studiableImage = defaultQuestionSectionData.b;
        StudiableAudio studiableAudio = defaultQuestionSectionData.c;
        if (studiableText != null && !StringsKt.O(studiableText.a) && studiableImage != null) {
            return new j(studiableText, studiableImage, studiableAudio);
        }
        if (studiableImage != null) {
            return new g(studiableImage);
        }
        if (studiableText != null) {
            return new k(studiableText, studiableAudio);
        }
        throw new IllegalStateException("DefaultQuestionSectionData cannot have both null text and image");
    }
}
