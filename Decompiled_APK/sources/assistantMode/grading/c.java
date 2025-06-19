package assistantMode.grading;

import assistantMode.types.Feedback;
import assistantMode.types.GradedAnswer;
import assistantMode.types.MatchingGameAnswer;
import assistantMode.types.QuestionElement;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements d {
    public final LinkedHashSet a;
    public final Map b;

    public c(LinkedHashSet validMatches, Map expectedMatchElements) {
        Intrinsics.checkNotNullParameter(validMatches, "validMatches");
        Intrinsics.checkNotNullParameter(expectedMatchElements, "expectedMatchElements");
        this.a = validMatches;
        this.b = expectedMatchElements;
    }

    @Override // assistantMode.grading.d
    public final Object a(v vVar, J2 j2, kotlin.coroutines.jvm.internal.c cVar) {
        if (!(vVar instanceof MatchingGameAnswer)) {
            throw new IllegalArgumentException(("MatchingGameGrader expected MatchingGameAnswer, but received " + vVar).toString());
        }
        if (!(j2 instanceof f)) {
            throw new IllegalArgumentException(("MatchingGameGrader expected QuestionGraderSettings.None, but received " + j2).toString());
        }
        MatchingGameAnswerPair matchingGameAnswerPair = ((MatchingGameAnswer) vVar).a;
        LinkedHashSet<MatchingGameAnswerPair> linkedHashSet = this.a;
        boolean zContains = linkedHashSet.contains(matchingGameAnswerPair);
        for (MatchingGameAnswerPair value : linkedHashSet) {
            int i = value.a;
            if (i == matchingGameAnswerPair.a) {
                Object obj = this.b.get(new Integer(i));
                if (obj == null) {
                    throw new IllegalStateException(("MatchingGameGrader could not find question element for option index " + value.a).toString());
                }
                v.Companion.getClass();
                Intrinsics.checkNotNullParameter(value, "value");
                return new GradedAnswer(zContains, new Feedback(vVar, new MatchingGameAnswer(value), (QuestionElement) obj, (Boolean) null, 24), null, new LocalGradedAnswerMetadata());
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
        return f.a;
    }

    @Override // assistantMode.grading.d
    public final v c() {
        throw new Error("There is no specific expected answer for Match game because there are multiple 'prompts' and 'answers'. Use grader.grade() to get expectedAnswer for a specific prompt.");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a.equals(cVar.a) && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MatchingGameGrader(validMatches=" + this.a + ", expectedMatchElements=" + this.b + ")";
    }
}
