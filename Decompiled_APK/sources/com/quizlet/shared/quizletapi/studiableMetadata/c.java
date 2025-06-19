package com.quizlet.shared.quizletapi.studiableMetadata;

import assistantMode.enums.q;
import assistantMode.refactored.types.StudiableMetadataContent;
import com.quizlet.shared.models.api.base.DataWrapper;
import com.quizlet.shared.models.api.base.ModelWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function1 {
    public static final c a = new c(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        List list;
        q qVar;
        DataWrapper dataWrapper;
        List list2;
        ModelWrapper modelWrapper;
        ModelWrapper modelWrapper2;
        QuizletApiThreeResponse quizletApiThreeResponse = (QuizletApiThreeResponse) obj;
        StudiableMetadataContent studiableMetadataContent = null;
        List list3 = (quizletApiThreeResponse == null || (modelWrapper2 = quizletApiThreeResponse.a) == null) ? null : modelWrapper2.g;
        if (list3 != null && !list3.isEmpty()) {
            if (quizletApiThreeResponse == null || (modelWrapper = quizletApiThreeResponse.a) == null || (list = modelWrapper.g) == null) {
                list = K.a;
            }
            if (quizletApiThreeResponse == null || (dataWrapper = quizletApiThreeResponse.b) == null || (list2 = dataWrapper.g) == null || (qVar = (q) CollectionsKt.L(list2)) == null) {
                qVar = q.c;
            }
            studiableMetadataContent = new StudiableMetadataContent(list, qVar);
        }
        return studiableMetadataContent;
    }
}
