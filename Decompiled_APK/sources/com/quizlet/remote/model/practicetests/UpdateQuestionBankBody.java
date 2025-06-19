package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UpdateQuestionBankBody {
    public final long a;
    public final boolean b;

    public UpdateQuestionBankBody(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UpdateQuestionBankBody)) {
            return false;
        }
        UpdateQuestionBankBody updateQuestionBankBody = (UpdateQuestionBankBody) obj;
        return this.a == updateQuestionBankBody.a && this.b == updateQuestionBankBody.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "UpdateQuestionBankBody(creatorId=" + this.a + ", private=" + this.b + ")";
    }
}
