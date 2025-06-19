package com.quizlet.explanations.solution.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h extends com.google.mlkit.common.model.a {
    public final String a;
    public final String b;
    public final long c;

    public h(long j, String questionId, String questionSlug) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        Intrinsics.checkNotNullParameter(questionSlug, "questionSlug");
        this.a = questionId;
        this.b = questionSlug;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b) && this.c == hVar.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionMetadata(questionId=");
        sb.append(this.a);
        sb.append(", questionSlug=");
        sb.append(this.b);
        sb.append(", questionLongId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
