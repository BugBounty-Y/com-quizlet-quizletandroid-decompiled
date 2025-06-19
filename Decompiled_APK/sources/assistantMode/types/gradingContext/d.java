package assistantMode.types.gradingContext;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import assistantMode.grading.LocalGradedAnswerMetadata;
import assistantMode.grading.f;
import assistantMode.types.Feedback;
import assistantMode.types.GradedAnswer;
import assistantMode.types.MatchingAnswer;
import assistantMode.types.QuestionElement;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements assistantMode.grading.d {
    public final List a;
    public final ArrayList b;
    public final ArrayList c;

    public d(List expectedAnswerDescriptions, ArrayList expectedAnswerIndexes, ArrayList validMatches) {
        Intrinsics.checkNotNullParameter(expectedAnswerDescriptions, "expectedAnswerDescriptions");
        Intrinsics.checkNotNullParameter(expectedAnswerIndexes, "expectedAnswerIndexes");
        Intrinsics.checkNotNullParameter(validMatches, "validMatches");
        this.a = expectedAnswerDescriptions;
        this.b = expectedAnswerIndexes;
        this.c = validMatches;
    }

    @Override // assistantMode.grading.d
    public final Object a(v vVar, J2 j2, kotlin.coroutines.jvm.internal.c cVar) {
        if (!(vVar instanceof MatchingAnswer)) {
            throw new IllegalArgumentException(("MatchingQuestionGrader expected MatchingAnswer, but received " + vVar).toString());
        }
        if (!(j2 instanceof f)) {
            throw new IllegalArgumentException(("MatchingQuestionGrader expected QuestionGraderSettings.None, but received " + j2).toString());
        }
        MatchingAnswer matchingAnswer = (MatchingAnswer) vVar;
        int iA = (int) matchingAnswer.a.a();
        Long lB = matchingAnswer.a.b();
        Integer num = lB != null ? new Integer((int) lB.longValue()) : null;
        return new GradedAnswer(num == null ? false : this.c.contains(new ExpectedMatchQuestionPair(iA, num.intValue())), new Feedback(vVar, new MatchingAnswer(new ExpectedMatchQuestionPair(iA, ((Number) this.b.get(iA)).intValue())), (QuestionElement) this.a.get(iA), (Boolean) null, 24), null, new LocalGradedAnswerMetadata());
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
        return f.a;
    }

    @Override // assistantMode.grading.d
    public final v c() {
        throw new Error("There is no specific expected answer for match questions because there are multiple prompts and answers. Use grader.grade() to get expectedAnswer for a specific prompt.");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b) && this.c.equals(dVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.h(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MatchingQuestionGrader(expectedAnswerDescriptions=");
        sb.append(this.a);
        sb.append(", expectedAnswerIndexes=");
        sb.append(this.b);
        sb.append(", validMatches=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
