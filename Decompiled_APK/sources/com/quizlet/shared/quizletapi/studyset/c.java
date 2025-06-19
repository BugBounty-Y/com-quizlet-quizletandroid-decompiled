package com.quizlet.shared.quizletapi.studyset;

import com.quizlet.shared.models.api.base.ModelWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.studyset.TermsResponse;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function1 {
    public static final c a = new c(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ModelWrapper modelWrapper;
        List list;
        QuizletApiThreeResponse quizletApiThreeResponse = (QuizletApiThreeResponse) obj;
        if (quizletApiThreeResponse == null || (modelWrapper = quizletApiThreeResponse.a) == null || (list = modelWrapper.i) == null) {
            return null;
        }
        return new TermsResponse(list);
    }
}
