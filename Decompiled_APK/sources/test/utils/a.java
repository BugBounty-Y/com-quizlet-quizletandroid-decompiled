package test.utils;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final Long a;
    public final assistantMode.grading.d b;

    public a(Long l, assistantMode.grading.d grader) {
        Intrinsics.checkNotNullParameter(grader, "grader");
        this.a = l;
        this.b = grader;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        Long l = this.a;
        return this.b.hashCode() + ((l == null ? 0 : l.hashCode()) * 31);
    }

    public final String toString() {
        return "AssociatedQuestionData(studiableItemId=" + this.a + ", grader=" + this.b + ")";
    }
}
