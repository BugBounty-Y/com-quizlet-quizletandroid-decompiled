package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QuestionBanksResponse {
    public final List a;

    public QuestionBanksResponse(List questionBank) {
        Intrinsics.checkNotNullParameter(questionBank, "questionBank");
        this.a = questionBank;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof QuestionBanksResponse) && Intrinsics.b(this.a, ((QuestionBanksResponse) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("QuestionBanksResponse(questionBank="), this.a);
    }

    public QuestionBanksResponse(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list);
    }
}
