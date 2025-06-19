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
public final class FlashcardsSubmitAction implements a {

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
            return FlashcardsSubmitAction$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardsSubmitAction(int i, RevealSelfAssessmentQuestion revealSelfAssessmentQuestion, RevealSelfAssessmentAnswer revealSelfAssessmentAnswer, Object obj) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FlashcardsSubmitAction$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = revealSelfAssessmentQuestion;
        this.b = revealSelfAssessmentAnswer;
        this.c = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsSubmitAction)) {
            return false;
        }
        FlashcardsSubmitAction flashcardsSubmitAction = (FlashcardsSubmitAction) obj;
        return Intrinsics.b(this.a, flashcardsSubmitAction.a) && Intrinsics.b(this.b, flashcardsSubmitAction.b) && Intrinsics.b(this.c, flashcardsSubmitAction.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.a.hashCode() + (this.a.hashCode() * 31)) * 31;
        Object obj = this.c;
        return iHashCode + (obj == null ? 0 : obj.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsSubmitAction(question=");
        sb.append(this.a);
        sb.append(", answer=");
        sb.append(this.b);
        sb.append(", clientData=");
        return android.support.v4.media.session.a.s(sb, this.c, ")");
    }

    public FlashcardsSubmitAction(RevealSelfAssessmentQuestion question, RevealSelfAssessmentAnswer answer, Object obj) {
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = question;
        this.b = answer;
        this.c = obj;
    }
}
