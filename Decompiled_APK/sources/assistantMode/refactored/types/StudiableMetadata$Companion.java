package assistantMode.refactored.types;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class StudiableMetadata$Companion {
    public static final /* synthetic */ StudiableMetadata$Companion a = new StudiableMetadata$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.refactored.types.StudiableMetadata", K.a(f.class), new kotlin.reflect.c[]{K.a(AlternativeQuestion.class), K.a(CardSideQuestionTypeRecommendation.class), K.a(FillInTheBlankMultipleChoiceQuestionStudiableMetadata.class), K.a(FillInTheBlankQuestionStudiableMetadata.class), K.a(MLMCQDistractorStudiableMetadata.class), K.a(MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata.class), K.a(ParsedMultipleChoiceQuestionStudiableMetadata.class)}, new KSerializer[]{AlternativeQuestion$$serializer.INSTANCE, CardSideQuestionTypeRecommendation$$serializer.INSTANCE, FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE, FillInTheBlankQuestionStudiableMetadata$$serializer.INSTANCE, MLMCQDistractorStudiableMetadata$$serializer.INSTANCE, MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata$$serializer.INSTANCE, ParsedMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE}, new Annotation[0]);
    }
}
