package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.types.FlashcardsStepMetadata;
import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsQuestion implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {null, new kotlinx.serialization.e("assistantMode.refactored.types.flashcards.FlashcardsAction", K.a(a.class), new kotlin.reflect.c[]{K.a(FlashcardsBeginRoundActionClass.class), K.a(FlashcardsSubmitAction.class), K.a(FlashcardsUndoAction.class)}, new KSerializer[]{FlashcardsBeginRoundActionClass$$serializer.INSTANCE, FlashcardsSubmitAction$$serializer.INSTANCE, FlashcardsUndoAction$$serializer.INSTANCE}, new Annotation[0]), null, null};
    public final RevealSelfAssessmentQuestion a;
    public final a b;
    public final FlashcardsModeProgress c;
    public final FlashcardsStepMetadata d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardsQuestion(int i, RevealSelfAssessmentQuestion revealSelfAssessmentQuestion, a aVar, FlashcardsModeProgress flashcardsModeProgress, FlashcardsStepMetadata flashcardsStepMetadata) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, FlashcardsQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = revealSelfAssessmentQuestion;
        this.b = aVar;
        this.c = flashcardsModeProgress;
        this.d = flashcardsStepMetadata;
    }

    @Override // assistantMode.refactored.types.flashcards.f
    public final FlashcardsModeProgress a() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsQuestion)) {
            return false;
        }
        FlashcardsQuestion flashcardsQuestion = (FlashcardsQuestion) obj;
        return Intrinsics.b(this.a, flashcardsQuestion.a) && Intrinsics.b(this.b, flashcardsQuestion.b) && Intrinsics.b(this.c, flashcardsQuestion.c) && Intrinsics.b(this.d, flashcardsQuestion.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "FlashcardsQuestion(question=" + this.a + ", lastAction=" + this.b + ", progress=" + this.c + ", metadata=" + this.d + ")";
    }

    public FlashcardsQuestion(RevealSelfAssessmentQuestion question, a lastAction, FlashcardsModeProgress progress, FlashcardsStepMetadata metadata) {
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(lastAction, "lastAction");
        Intrinsics.checkNotNullParameter(progress, "progress");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = question;
        this.b = lastAction;
        this.c = progress;
        this.d = metadata;
    }
}
