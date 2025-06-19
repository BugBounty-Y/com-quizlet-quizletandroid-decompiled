package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class ExternalFlashcardsState {

    @NotNull
    public static final Companion Companion = new Companion();
    public final RevealSelfAssessmentQuestion a;
    public final boolean b;
    public final FlashcardsModeProgress c;
    public final int d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ExternalFlashcardsState$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ExternalFlashcardsState(int i, RevealSelfAssessmentQuestion revealSelfAssessmentQuestion, boolean z, FlashcardsModeProgress flashcardsModeProgress, int i2) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, ExternalFlashcardsState$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = revealSelfAssessmentQuestion;
        this.b = z;
        this.c = flashcardsModeProgress;
        this.d = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExternalFlashcardsState)) {
            return false;
        }
        ExternalFlashcardsState externalFlashcardsState = (ExternalFlashcardsState) obj;
        return Intrinsics.b(this.a, externalFlashcardsState.a) && this.b == externalFlashcardsState.b && Intrinsics.b(this.c, externalFlashcardsState.c) && this.d == externalFlashcardsState.d;
    }

    public final int hashCode() {
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = this.a;
        return Integer.hashCode(this.d) + ((this.c.hashCode() + d0.g((revealSelfAssessmentQuestion == null ? 0 : revealSelfAssessmentQuestion.hashCode()) * 31, 31, this.b)) * 31);
    }

    public final String toString() {
        return "ExternalFlashcardsState(question=" + this.a + ", hasActionAvailableToUndo=" + this.b + ", progress=" + this.c + ", shuffleRandomSeed=" + this.d + ")";
    }
}
