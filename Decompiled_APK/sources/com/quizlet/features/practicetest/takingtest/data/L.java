package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class L {
    public final String a;
    public final J b;

    public L(String questionBankId, J content) {
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = questionBankId;
        this.b = content;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return Intrinsics.b(this.a, l.a) && Intrinsics.b(this.b, l.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "QuestionContentWithQuestionBankId(questionBankId=" + this.a + ", content=" + this.b + ")";
    }
}
