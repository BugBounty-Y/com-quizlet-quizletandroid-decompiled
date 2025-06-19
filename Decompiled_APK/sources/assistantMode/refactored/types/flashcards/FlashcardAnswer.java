package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.types.RevealSelfAssessmentAnswer;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardAnswer {

    @NotNull
    public static final Companion Companion = new Companion();
    public final RevealSelfAssessmentAnswer a;
    public final RevealSelfAssessmentQuestion b;
    public final int c;
    public final long d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardAnswer$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardAnswer(int i, RevealSelfAssessmentAnswer revealSelfAssessmentAnswer, RevealSelfAssessmentQuestion revealSelfAssessmentQuestion, int i2, long j) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, FlashcardAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = revealSelfAssessmentAnswer;
        this.b = revealSelfAssessmentQuestion;
        this.c = i2;
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardAnswer)) {
            return false;
        }
        FlashcardAnswer flashcardAnswer = (FlashcardAnswer) obj;
        return Intrinsics.b(this.a, flashcardAnswer.a) && Intrinsics.b(this.b, flashcardAnswer.b) && this.c == flashcardAnswer.c && this.d == flashcardAnswer.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + d0.b(this.c, (this.b.hashCode() + (this.a.a.hashCode() * 31)) * 31, 31);
    }

    public final String toString() {
        return "FlashcardAnswer(answer=" + this.a + ", question=" + this.b + ", roundNum=" + this.c + ", timestamp=" + this.d + ")";
    }

    public FlashcardAnswer(RevealSelfAssessmentAnswer answer, RevealSelfAssessmentQuestion question, int i, long j) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = answer;
        this.b = question;
        this.c = i;
        this.d = j;
    }
}
