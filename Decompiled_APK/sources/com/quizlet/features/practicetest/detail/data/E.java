package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E {
    public final F a;
    public final Long b;
    public final Long c;

    public E(F content, Long l, Long l2) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = content;
        this.b = l;
        this.c = l2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E)) {
            return false;
        }
        E e = (E) obj;
        return Intrinsics.b(this.a, e.a) && Intrinsics.b(this.b, e.b) && Intrinsics.b(this.c, e.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Long l = this.b;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.c;
        return iHashCode2 + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "PracticeTestDetailUiResult(content=" + this.a + ", creatorId=" + this.b + ", setId=" + this.c + ")";
    }
}
