package com.quizlet.shared.models.api.exceptions;

import com.quizlet.shared.models.api.base.errors.QuizletApiError;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletApiException extends Exception {
    public final String a;
    public final Integer b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public QuizletApiException(QuizletApiError quizletApiError, String url) {
        super(quizletApiError != null ? quizletApiError.a : null, null);
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = quizletApiError != null ? quizletApiError.b : null;
        this.b = quizletApiError != null ? quizletApiError.c : null;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof QuizletApiException)) {
            return false;
        }
        QuizletApiException quizletApiException = (QuizletApiException) obj;
        return Intrinsics.b(getMessage(), quizletApiException.getMessage()) && Intrinsics.b(this.b, quizletApiException.b) && Intrinsics.b(this.a, quizletApiException.a);
    }
}
