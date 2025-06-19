package com.quizlet.explanations.sharing;

import com.quizlet.qutils.string.f;
import com.quizlet.qutils.string.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final g a;
    public final f b;

    public a(g subjectResData, f messageResData) {
        Intrinsics.checkNotNullParameter(subjectResData, "subjectResData");
        Intrinsics.checkNotNullParameter(messageResData, "messageResData");
        this.a = subjectResData;
        this.b = messageResData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a.equals(aVar.a) && this.b.equals(aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ExplanationsShareResData(subjectResData=" + this.a + ", messageResData=" + this.b + ")";
    }
}
