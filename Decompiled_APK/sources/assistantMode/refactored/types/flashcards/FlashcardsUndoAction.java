package assistantMode.refactored.types.flashcards;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.types.RevealSelfAssessmentAnswer;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsUndoAction implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {null, null, new kotlinx.serialization.a(K.a(Object.class), (KSerializer) null, new KSerializer[0])};
    public final RevealSelfAssessmentQuestion a;
    public final RevealSelfAssessmentAnswer b;
    public final Object c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsUndoAction$$serializer.INSTANCE;
        }
    }

    public FlashcardsUndoAction(RevealSelfAssessmentQuestion revealSelfAssessmentQuestion, FlashcardsSubmitAction submitAction) {
        Intrinsics.checkNotNullParameter(submitAction, "submitAction");
        RevealSelfAssessmentAnswer answer = submitAction.b;
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = revealSelfAssessmentQuestion;
        this.b = answer;
        this.c = submitAction.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsUndoAction)) {
            return false;
        }
        FlashcardsUndoAction flashcardsUndoAction = (FlashcardsUndoAction) obj;
        return Intrinsics.b(this.a, flashcardsUndoAction.a) && Intrinsics.b(this.b, flashcardsUndoAction.b) && Intrinsics.b(this.c, flashcardsUndoAction.c);
    }

    public final int hashCode() {
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = this.a;
        int iHashCode = (this.b.a.hashCode() + ((revealSelfAssessmentQuestion == null ? 0 : revealSelfAssessmentQuestion.hashCode()) * 31)) * 31;
        Object obj = this.c;
        return iHashCode + (obj != null ? obj.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsUndoAction(nextQuestion=");
        sb.append(this.a);
        sb.append(", answer=");
        sb.append(this.b);
        sb.append(", clientData=");
        return android.support.v4.media.session.a.s(sb, this.c, ")");
    }

    public /* synthetic */ FlashcardsUndoAction(int i, RevealSelfAssessmentQuestion revealSelfAssessmentQuestion, RevealSelfAssessmentAnswer revealSelfAssessmentAnswer, Object obj) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FlashcardsUndoAction$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = revealSelfAssessmentQuestion;
        this.b = revealSelfAssessmentAnswer;
        this.c = obj;
    }
}
