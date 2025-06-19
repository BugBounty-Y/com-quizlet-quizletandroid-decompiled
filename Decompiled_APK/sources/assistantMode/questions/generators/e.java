package assistantMode.questions.generators;

import assistantMode.grading.o;
import assistantMode.refactored.modelTypes.CustomMultipleChoiceQuestion;
import assistantMode.refactored.modelTypes.MultipleChoiceOption;
import assistantMode.refactored.types.MultipleChoiceQuestion;
import assistantMode.types.C1460g;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.m;

/* loaded from: classes.dex */
public final class e extends Q2 {
    public final C1460g a;
    public final Object b;
    public final List c;
    public final MultipleChoiceQuestion d;

    public e(C1460g questionConfig) {
        int i;
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        assistantMode.enums.k questionType = assistantMode.enums.k.d;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = questionConfig;
        kotlin.k kVarA = kotlin.l.a(m.a, new o(0, 2));
        this.b = kVarA;
        CustomMultipleChoiceQuestion customMultipleChoiceQuestion = questionConfig.a;
        List list = customMultipleChoiceQuestion.e;
        List listN0 = CollectionsKt.n0(B.n(customMultipleChoiceQuestion.g, (kotlin.random.e) kVarA.getValue()), new androidx.constraintlayout.core.e(6));
        this.c = listN0;
        QuestionMetadata questionMetadata = new QuestionMetadata(Long.valueOf(customMultipleChoiceQuestion.a), null, null, null, null, null, 248);
        QuestionElement questionElementE = N2.e(list);
        QuestionElement questionElementE2 = N2.e(customMultipleChoiceQuestion.f);
        ArrayList arrayList = new ArrayList(C.q(listN0, 10));
        Iterator it2 = listN0.iterator();
        while (it2.hasNext()) {
            arrayList.add(N2.e(((MultipleChoiceOption) it2.next()).d));
        }
        List list2 = this.c;
        if (list2 == null || !list2.isEmpty()) {
            Iterator it3 = list2.iterator();
            i = 0;
            while (it3.hasNext()) {
                if (((MultipleChoiceOption) it3.next()).b && (i = i + 1) < 0) {
                    B.o();
                    throw null;
                }
            }
        } else {
            i = 0;
        }
        this.d = new MultipleChoiceQuestion(questionElementE, questionElementE2, arrayList, i == 1, questionMetadata);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        ArrayList arrayList = new ArrayList();
        List list = this.c;
        Iterator it2 = list.iterator();
        int i = 0;
        int i2 = 0;
        while (true) {
            if (!it2.hasNext()) {
                Set setA0 = CollectionsKt.A0(arrayList);
                ArrayList arrayList2 = new ArrayList(C.q(list, 10));
                for (Object obj : list) {
                    int i3 = i + 1;
                    if (i < 0) {
                        B.p();
                        throw null;
                    }
                    arrayList2.add(new Pair(Integer.valueOf(i), N2.e(((MultipleChoiceOption) obj).e)));
                    i = i3;
                }
                return new assistantMode.types.gradingContext.e(setA0, null, V.k(arrayList2));
            }
            Object next = it2.next();
            int i4 = i2 + 1;
            if (i2 < 0) {
                B.p();
                throw null;
            }
            Integer numValueOf = ((MultipleChoiceOption) next).b ? Integer.valueOf(i2) : null;
            if (numValueOf != null) {
                arrayList.add(numValueOf);
            }
            i2 = i4;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        return A.b(Long.valueOf(this.a.a.a));
    }
}
