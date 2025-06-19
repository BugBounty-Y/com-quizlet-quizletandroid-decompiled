package com.quizlet.features.infra.basestudy.manager;

import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ e(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                C1 defaultStudyPath = (C1) obj;
                Intrinsics.checkNotNullParameter(defaultStudyPath, "defaultStudyPath");
                f.a(this.b, defaultStudyPath);
                break;
            default:
                StudyableModel studyable = (StudyableModel) obj;
                Intrinsics.checkNotNullParameter(studyable, "studyable");
                String title = studyable.getTitle();
                if (title == null) {
                    title = "";
                }
                String str = title;
                f fVar = this.b;
                com.quizlet.data.repository.user.a aVar = fVar.h;
                Long studyableId = studyable.getStudyableId();
                Intrinsics.checkNotNullExpressionValue(studyableId, "getStudyableId(...)");
                long jLongValue = studyableId.longValue();
                G1 studyableType = studyable.getStudyableType();
                Intrinsics.checkNotNullExpressionValue(studyableType, "getStudyableType(...)");
                aVar.s(fVar.p, str, jLongValue, studyableType, fVar.o);
                break;
        }
    }
}
