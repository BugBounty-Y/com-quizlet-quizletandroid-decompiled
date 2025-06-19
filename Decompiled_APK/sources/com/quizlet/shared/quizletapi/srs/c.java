package com.quizlet.shared.quizletapi.srs;

import com.quizlet.shared.models.api.base.DataWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function1 {
    public static final c a = new c(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        DataWrapper dataWrapper;
        QuizletApiThreeResponse quizletApiThreeResponse = (QuizletApiThreeResponse) obj;
        if (quizletApiThreeResponse == null || (dataWrapper = quizletApiThreeResponse.b) == null) {
            return null;
        }
        return dataWrapper.b;
    }
}
