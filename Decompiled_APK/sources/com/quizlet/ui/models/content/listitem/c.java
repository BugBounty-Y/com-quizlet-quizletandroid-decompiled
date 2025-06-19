package com.quizlet.ui.models.content.listitem;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final String b;

    public c(String questionUuid, String prompt) {
        Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        this.a = questionUuid;
        this.b = prompt;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExpertSolutionContentMetadata(questionUuid=");
        sb.append(this.a);
        sb.append(", prompt=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
