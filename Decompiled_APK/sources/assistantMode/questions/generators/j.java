package assistantMode.questions.generators;

import assistantMode.refactored.modelTypes.CardSideDistractor;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestion;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
import assistantMode.types.C1457d;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.o;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j extends Q2 {
    public final C1457d a;
    public final MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata b;
    public final QuestionElement c;
    public final ArrayList d;
    public final List e;
    public final Set f;
    public final MultipleChoiceSelectAllThatApplyQuestion g;

    public j(o questionConfig, assistantMode.utils.h studyableMaterialDataSource) {
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        assistantMode.enums.k questionType = assistantMode.enums.k.m;
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = questionConfig.b;
        MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata multipleChoiceSelectAllThatApplyQuestionStudiableMetadata = questionConfig.a;
        this.b = multipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
        this.c = new QuestionElement(assistantMode.utils.g.o(A.b(multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.g)));
        List list = multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.h;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(new QuestionElement(assistantMode.utils.g.o(((CardSideDistractor) it2.next()).a)));
        }
        this.d = arrayList;
        List list2 = this.b.i;
        ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            arrayList2.add(new QuestionElement(assistantMode.utils.g.o(((CardSideDistractor) it3.next()).a)));
        }
        this.e = A.c(CollectionsKt.B0(this.d, arrayList2));
        ArrayList arrayList3 = this.d;
        ArrayList arrayList4 = new ArrayList(C.q(arrayList3, 10));
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            arrayList4.add(Integer.valueOf(this.e.indexOf((QuestionElement) it4.next())));
        }
        Set setA0 = CollectionsKt.A0(arrayList4);
        this.f = setA0;
        QuestionElement questionElement = this.c;
        List list3 = this.e;
        Integer numValueOf = Integer.valueOf(setA0.size());
        Long lValueOf = Long.valueOf(this.a.a.a.a);
        C1457d c1457d = this.a;
        this.g = new MultipleChoiceSelectAllThatApplyQuestion(questionElement, list3, numValueOf, new QuestionMetadata(lValueOf, c1457d.b, c1457d.c, null, studyableMaterialDataSource.h(c1457d.a.a.a), studyableMaterialDataSource.j(), 152));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        return new assistantMode.grading.a(this.f);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        return this.g;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        return A.b(Long.valueOf(this.a.a.a.a));
    }
}
