package com.quizlet.shared.quizletapi.studynotes;

import com.quizlet.shared.models.api.base.DataWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.notes.CreateStudyNotesResponse;
import com.quizlet.shared.models.api.notes.StudyNotesArtifactsResponse;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class b extends r implements Function1 {
    public static final b b = new b(1, 0);
    public static final b c = new b(1, 1);
    public static final b d = new b(1, 2);
    public static final b e = new b(1, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        DataWrapper dataWrapper;
        List list;
        DataWrapper dataWrapper2;
        List list2;
        com.quizlet.shared.enums.studynotes.f fVar;
        DataWrapper dataWrapper3;
        List list3;
        DataWrapper dataWrapper4;
        switch (this.a) {
            case 0:
                QuizletApiThreeResponse quizletApiThreeResponse = (QuizletApiThreeResponse) obj;
                if (quizletApiThreeResponse == null || (dataWrapper = quizletApiThreeResponse.b) == null || (list = dataWrapper.c) == null) {
                    return null;
                }
                return (CreateStudyNotesResponse) CollectionsKt.firstOrNull(list);
            case 1:
                QuizletApiThreeResponse quizletApiThreeResponse2 = (QuizletApiThreeResponse) obj;
                if (quizletApiThreeResponse2 == null || (dataWrapper2 = quizletApiThreeResponse2.b) == null || (list2 = dataWrapper2.d) == null) {
                    return null;
                }
                ArrayList arrayList = new ArrayList();
                for (Object obj2 : list2) {
                    StudyNotesArtifactsResponse studyNotesArtifactsResponse = (StudyNotesArtifactsResponse) obj2;
                    studyNotesArtifactsResponse.getClass();
                    com.quizlet.shared.enums.studynotes.f[] fVarArrValues = com.quizlet.shared.enums.studynotes.f.values();
                    int length = fVarArrValues.length;
                    int i = 0;
                    while (true) {
                        if (i < length) {
                            fVar = fVarArrValues[i];
                            if (!Intrinsics.b(fVar.getValue(), studyNotesArtifactsResponse.d)) {
                                i++;
                            }
                        } else {
                            fVar = null;
                        }
                    }
                    if (fVar != null) {
                        arrayList.add(obj2);
                    }
                }
                return arrayList;
            case 2:
                QuizletApiThreeResponse quizletApiThreeResponse3 = (QuizletApiThreeResponse) obj;
                if (quizletApiThreeResponse3 == null || (dataWrapper3 = quizletApiThreeResponse3.b) == null || (list3 = dataWrapper3.d) == null) {
                    return null;
                }
                return (StudyNotesArtifactsResponse) CollectionsKt.firstOrNull(list3);
            default:
                QuizletApiThreeResponse quizletApiThreeResponse4 = (QuizletApiThreeResponse) obj;
                if (quizletApiThreeResponse4 == null || (dataWrapper4 = quizletApiThreeResponse4.b) == null) {
                    return null;
                }
                return dataWrapper4.e;
        }
    }
}
