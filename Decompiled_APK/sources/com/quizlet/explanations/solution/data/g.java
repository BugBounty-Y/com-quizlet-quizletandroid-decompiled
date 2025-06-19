package com.quizlet.explanations.solution.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g extends com.google.mlkit.common.model.a {
    public final long a;
    public final String b;
    public final String c;

    public g(long j, String textbookIsbn, String exerciseId) {
        Intrinsics.checkNotNullParameter(textbookIsbn, "textbookIsbn");
        Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
        this.a = j;
        this.b = textbookIsbn;
        this.c = exerciseId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseMetadata(textbookId=");
        sb.append(this.a);
        sb.append(", textbookIsbn=");
        sb.append(this.b);
        sb.append(", exerciseId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
