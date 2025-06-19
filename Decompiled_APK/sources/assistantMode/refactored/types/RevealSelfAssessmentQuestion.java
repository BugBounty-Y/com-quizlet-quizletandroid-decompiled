package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.types.F;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class RevealSelfAssessmentQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public final QuestionElement a;
    public final QuestionElement b;
    public final QuestionElement c;
    public final QuestionMetadata d;
    public final k e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RevealSelfAssessmentQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RevealSelfAssessmentQuestion(int i, QuestionElement questionElement, QuestionElement questionElement2, QuestionElement questionElement3, QuestionMetadata questionMetadata, k kVar) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, RevealSelfAssessmentQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = questionElement2;
        this.c = questionElement3;
        this.d = questionMetadata;
        if ((i & 16) == 0) {
            this.e = k.f;
        } else {
            this.e = kVar;
        }
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RevealSelfAssessmentQuestion)) {
            return false;
        }
        RevealSelfAssessmentQuestion revealSelfAssessmentQuestion = (RevealSelfAssessmentQuestion) obj;
        return Intrinsics.b(this.a, revealSelfAssessmentQuestion.a) && Intrinsics.b(this.b, revealSelfAssessmentQuestion.b) && Intrinsics.b(this.c, revealSelfAssessmentQuestion.c) && Intrinsics.b(this.d, revealSelfAssessmentQuestion.d);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.d;
    }

    public final int hashCode() {
        int iF = d0.f(this.a.a.hashCode() * 31, 31, this.b.a);
        QuestionElement questionElement = this.c;
        return this.d.hashCode() + ((iF + (questionElement == null ? 0 : questionElement.a.hashCode())) * 31);
    }

    public final String toString() {
        return "RevealSelfAssessmentQuestion(front=" + this.a + ", back=" + this.b + ", hint=" + this.c + ", metadata=" + this.d + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.d;
    }

    public RevealSelfAssessmentQuestion(QuestionElement front, QuestionElement back, QuestionElement questionElement, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(front, "front");
        Intrinsics.checkNotNullParameter(back, "back");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = front;
        this.b = back;
        this.c = questionElement;
        this.d = metadata;
        this.e = k.f;
    }
}
