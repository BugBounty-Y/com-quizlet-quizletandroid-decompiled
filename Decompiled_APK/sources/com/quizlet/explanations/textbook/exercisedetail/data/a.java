package com.quizlet.explanations.textbook.exercisedetail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final boolean b;

    public a(String id, boolean z) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.a = id;
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
        return "NextExercise(id=" + this.a + ", isDeepLinkState=" + this.b + ")";
    }
}
