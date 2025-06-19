package assistantMode.questions.generators;

import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.types.B;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.R2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i extends Q2 {
    public final B a;
    public final C1454a b;
    public final RevealSelfAssessmentQuestion c;

    public i(B questionConfig, assistantMode.enums.k questionType, assistantMode.utils.h studyableMaterialDataSource) {
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = questionConfig;
        C1454a c1454a = (C1454a) CollectionsKt.L(questionConfig.a());
        this.b = c1454a;
        C1457d c1457d = questionConfig.a;
        QuestionElement questionElementC = N2.c(c1454a, c1457d.b);
        QuestionElement questionElementC2 = N2.c(c1454a, c1457d.c);
        long j = c1454a.a.a;
        this.c = new RevealSelfAssessmentQuestion(questionElementC, questionElementC2, R2.d(questionConfig, c1454a), new QuestionMetadata(Long.valueOf(j), c1457d.b, c1457d.c, null, studyableMaterialDataSource.h(j), studyableMaterialDataSource.j(), 136));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        return new assistantMode.grading.a(N2.c(this.b, this.a.a.c));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        List listA = this.a.a();
        ArrayList arrayList = new ArrayList(C.q(listA, 10));
        Iterator it2 = listA.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((C1454a) it2.next()).a.a));
        }
        return arrayList;
    }
}
