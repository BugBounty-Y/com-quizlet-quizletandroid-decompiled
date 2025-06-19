package com.quizlet.studiablemodels;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public abstract class StudiableQuestion extends StudiableStep {
    public abstract StudiableQuestionMetadata a();

    public final QuestionSectionData b() {
        if (this instanceof MultipleChoiceStudiableQuestion) {
            return ((MultipleChoiceStudiableQuestion) this).b;
        }
        if (this instanceof RevealSelfAssessmentStudiableQuestion) {
            return ((RevealSelfAssessmentStudiableQuestion) this).b;
        }
        if (this instanceof TrueFalseStudiableQuestion) {
            return ((TrueFalseStudiableQuestion) this).b;
        }
        if (this instanceof WrittenStudiableQuestion) {
            return ((WrittenStudiableQuestion) this).b;
        }
        if (this instanceof FillInTheBlankStudiableQuestion) {
            return ((FillInTheBlankStudiableQuestion) this).b;
        }
        throw new IllegalArgumentException("No prompt for given question type: ".concat(getClass().getSimpleName()));
    }
}
