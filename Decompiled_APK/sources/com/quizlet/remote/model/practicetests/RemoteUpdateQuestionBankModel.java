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
public final class RemoteUpdateQuestionBankModel {
    public final List a;

    public RemoteUpdateQuestionBankModel(List questionBank) {
        Intrinsics.checkNotNullParameter(questionBank, "questionBank");
        this.a = questionBank;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RemoteUpdateQuestionBankModel) && Intrinsics.b(this.a, ((RemoteUpdateQuestionBankModel) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("RemoteUpdateQuestionBankModel(questionBank="), this.a);
    }

    public RemoteUpdateQuestionBankModel(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list);
    }
}
