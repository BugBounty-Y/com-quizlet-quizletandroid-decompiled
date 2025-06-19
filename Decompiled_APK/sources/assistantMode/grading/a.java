package assistantMode.grading;

import androidx.camera.camera2.internal.AbstractC0147y;
import assistantMode.enums.EnumC1448b;
import assistantMode.types.Feedback;
import assistantMode.types.GradedAnswer;
import assistantMode.types.MultiPartAnswer;
import assistantMode.types.OptionIndicesAnswer;
import assistantMode.types.QuestionElement;
import assistantMode.types.RevealSelfAssessmentAnswer;
import assistantMode.types.v;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements d {
    public final /* synthetic */ int a = 2;
    public final Object b;

    public a(LinkedHashMap correctAnswerMap) {
        Intrinsics.checkNotNullParameter(correctAnswerMap, "correctAnswerMap");
        this.b = correctAnswerMap;
    }

    @Override // assistantMode.grading.d
    public final Object a(v vVar, J2 j2, kotlin.coroutines.jvm.internal.c cVar) {
        Boolean boolValueOf;
        switch (this.a) {
            case 0:
                boolean z = true;
                if (!(vVar == null ? true : vVar instanceof MultiPartAnswer)) {
                    throw new IllegalArgumentException(("FITBMCQGrader expected MultiPartAnswer? but received " + vVar).toString());
                }
                Feedback feedback = new Feedback(vVar, c(), (QuestionElement) null, (Boolean) null, 24);
                if (vVar == null) {
                    return new GradedAnswer(false, feedback, null, new LocalGradedAnswerMetadata());
                }
                LinkedHashMap linkedHashMap = (LinkedHashMap) this.b;
                Set setKeySet = linkedHashMap.keySet();
                if (!(setKeySet instanceof Collection) || !setKeySet.isEmpty()) {
                    Iterator it2 = setKeySet.iterator();
                    while (true) {
                        if (it2.hasNext()) {
                            int iIntValue = ((Number) it2.next()).intValue();
                            if (!Intrinsics.b(linkedHashMap.get(new Integer(iIntValue)), ((MultiPartAnswer) vVar).a.get(new Integer(iIntValue)))) {
                                z = false;
                            }
                        }
                    }
                }
                return new GradedAnswer(z, feedback, null, new LocalGradedAnswerMetadata());
            case 1:
                boolean z2 = true;
                if (!(vVar == null ? true : vVar instanceof OptionIndicesAnswer)) {
                    throw new IllegalArgumentException(("SATAGrader expected OptionIndicesAnswer? but received " + vVar).toString());
                }
                Set set = (Set) this.b;
                if (vVar != null) {
                    Set set2 = ((OptionIndicesAnswer) vVar).a;
                    if (set2.size() != set.size() && !set2.isEmpty()) {
                        z2 = false;
                    }
                    boolValueOf = Boolean.valueOf(z2);
                } else {
                    boolValueOf = null;
                }
                Feedback feedback2 = new Feedback(vVar, (boolValueOf == null || boolValueOf.booleanValue() || vVar == null) ? c() : new OptionIndicesAnswer(CollectionsKt.Q(set, ((OptionIndicesAnswer) vVar).a)), (QuestionElement) null, boolValueOf, 8);
                return vVar == null ? new GradedAnswer(false, feedback2, null, new LocalGradedAnswerMetadata()) : new GradedAnswer(Intrinsics.b(((OptionIndicesAnswer) vVar).a, set), feedback2, null, new LocalGradedAnswerMetadata());
            default:
                if (!(vVar == null ? true : vVar instanceof RevealSelfAssessmentAnswer)) {
                    throw new IllegalArgumentException(("RevealSelfAssessmentGrader expected RevealSelfAssessmentAnswer? but received " + vVar).toString());
                }
                if (!(j2 instanceof f)) {
                    throw new IllegalArgumentException(("RevealSelfAssessmentGrader expected QuestionGraderSettings.None, but received " + j2).toString());
                }
                Feedback feedback3 = new Feedback(vVar, c(), (QuestionElement) this.b, (Boolean) null, 24);
                if (vVar == null) {
                    return new GradedAnswer(false, feedback3, null, new LocalGradedAnswerMetadata());
                }
                EnumC1448b enumC1448b = EnumC1448b.c;
                EnumC1448b enumC1448b2 = ((RevealSelfAssessmentAnswer) vVar).a;
                if (enumC1448b2 == enumC1448b || enumC1448b2 == EnumC1448b.d) {
                    return new GradedAnswer(enumC1448b2 == enumC1448b, feedback3, null, new LocalGradedAnswerMetadata());
                }
                throw new IllegalArgumentException(AbstractC0147y.d("Unexpected answer for RevealSelfAssessmentGrader. Expected KNOW or DO_NOT_KNOW, but received ", enumC1448b2.name()).toString());
        }
    }

    @Override // assistantMode.grading.d
    public final J2 b(grading.core.d assistantSettings) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
                break;
            default:
                Intrinsics.checkNotNullParameter(assistantSettings, "assistantSettings");
                break;
        }
        return f.a;
    }

    @Override // assistantMode.grading.d
    public final v c() {
        switch (this.a) {
            case 0:
                return new MultiPartAnswer((LinkedHashMap) this.b);
            case 1:
                return new OptionIndicesAnswer((Set) this.b);
            default:
                return new RevealSelfAssessmentAnswer(EnumC1448b.c);
        }
    }

    public a(Set correctOptionIndices) {
        Intrinsics.checkNotNullParameter(correctOptionIndices, "correctOptionIndices");
        this.b = correctOptionIndices;
    }

    public a(QuestionElement expectedAnswerDescription) {
        Intrinsics.checkNotNullParameter(expectedAnswerDescription, "expectedAnswerDescription");
        this.b = expectedAnswerDescription;
    }
}
