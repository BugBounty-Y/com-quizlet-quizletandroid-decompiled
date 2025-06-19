package assistantMode.refactored.types;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class Question$Companion {
    public static final /* synthetic */ Question$Companion a = new Question$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.refactored.types.Question", K.a(d.class), new kotlin.reflect.c[]{K.a(FillInTheBlankMultipleChoiceQuestion.class), K.a(FillInTheBlankQuestion.class), K.a(MixedOptionMatchingQuestion.class), K.a(MultipleChoiceQuestion.class), K.a(MultipleChoiceSelectAllThatApplyQuestion.class), K.a(RevealSelfAssessmentQuestion.class), K.a(SeparatedOptionMatchingQuestion.class), K.a(SpellingQuestion.class), K.a(TrueFalseQuestion.class), K.a(WrittenQuestion.class)}, new KSerializer[]{FillInTheBlankMultipleChoiceQuestion$$serializer.INSTANCE, FillInTheBlankQuestion$$serializer.INSTANCE, MixedOptionMatchingQuestion$$serializer.INSTANCE, MultipleChoiceQuestion$$serializer.INSTANCE, MultipleChoiceSelectAllThatApplyQuestion$$serializer.INSTANCE, RevealSelfAssessmentQuestion$$serializer.INSTANCE, SeparatedOptionMatchingQuestion$$serializer.INSTANCE, SpellingQuestion$$serializer.INSTANCE, TrueFalseQuestion$$serializer.INSTANCE, WrittenQuestion$$serializer.INSTANCE}, new Annotation[0]);
    }
}
