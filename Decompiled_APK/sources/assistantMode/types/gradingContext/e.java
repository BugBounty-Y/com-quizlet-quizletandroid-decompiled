package assistantMode.types.gradingContext;

import assistantMode.grading.LocalGradedAnswerMetadata;
import assistantMode.types.C;
import assistantMode.types.Feedback;
import assistantMode.types.GradedAnswer;
import assistantMode.types.OptionIndexAnswer;
import assistantMode.types.OptionIndicesAnswer;
import assistantMode.types.QuestionElement;
import assistantMode.types.v;
import assistantMode.utils.g;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.M;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e implements assistantMode.grading.d {
    public final Set a;
    public final QuestionElement b;
    public final Map c;
    public final ArrayList d;

    public e(Set correctOptionIndices, QuestionElement questionElement, Map map) {
        Intrinsics.checkNotNullParameter(correctOptionIndices, "correctOptionIndices");
        this.a = correctOptionIndices;
        this.b = questionElement;
        this.c = map;
        this.d = new ArrayList();
    }

    @Override // assistantMode.grading.d
    public final Object a(v vVar, J2 j2, kotlin.coroutines.jvm.internal.c cVar) {
        Object objB;
        if (!(vVar == null ? true : vVar instanceof C)) {
            throw new IllegalArgumentException(("MultipleChoiceGrader expected SingleOrMultiIndexAnswer? but received " + vVar).toString());
        }
        if (!(j2 instanceof assistantMode.grading.e)) {
            throw new IllegalArgumentException(("MultipleChoiceGrader expected QuestionGraderSettings.MultipleChoice, but received " + j2).toString());
        }
        C c = (C) vVar;
        if (c instanceof OptionIndexAnswer) {
            objB = Z.b(Integer.valueOf((int) ((OptionIndexAnswer) c).a));
        } else if (c instanceof OptionIndicesAnswer) {
            objB = ((OptionIndicesAnswer) c).a;
        } else {
            if (c != null) {
                throw new NoWhenBranchMatchedException();
            }
            objB = M.a;
        }
        Set set = this.a;
        boolean zB = Intrinsics.b(objB, set);
        grading.core.d dVar = ((assistantMode.grading.e) j2).a;
        ArrayList arrayList = this.d;
        boolean z = dVar.d && arrayList.size() < 1;
        boolean zB2 = Intrinsics.b(vVar, g.p(Z.b(new Integer(-1))));
        if (vVar != null) {
            arrayList.add(vVar);
        }
        LocalGradedAnswerMetadata localGradedAnswerMetadata = new LocalGradedAnswerMetadata();
        if (!z || zB || zB2) {
            return new GradedAnswer(zB, new Feedback(vVar, g.p(set), this.b, this.c, Boolean.TRUE), null, localGradedAnswerMetadata);
        }
        return new GradedAnswer(zB, new Feedback(vVar, g.p(M.a), (QuestionElement) null, Boolean.FALSE, 8), null, localGradedAnswerMetadata);
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
        return new assistantMode.grading.e(new grading.core.d(false, false, false, assistantSettings.d, 7));
    }

    @Override // assistantMode.grading.d
    public final v c() {
        return g.p(this.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        QuestionElement questionElement = this.b;
        int iHashCode2 = (iHashCode + (questionElement == null ? 0 : questionElement.a.hashCode())) * 31;
        Map map = this.c;
        return iHashCode2 + (map != null ? map.hashCode() : 0);
    }

    public final String toString() {
        return "MultipleChoiceGrader(correctOptionIndices=" + this.a + ", expectedAnswerDescription=" + this.b + ", explanations=" + this.c + ")";
    }
}
