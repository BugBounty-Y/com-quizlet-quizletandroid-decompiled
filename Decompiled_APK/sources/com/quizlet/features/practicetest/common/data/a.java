package com.quizlet.features.practicetest.common.data;

import com.quizlet.data.model.X0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final X0 a;
    public final boolean b;

    public a(X0 question, boolean z) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "PracticeTestDetailQuestion(question=" + this.a + ", isSupported=" + this.b + ")";
    }
}
