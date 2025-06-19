package com.quizlet.explanations.myexplanations.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class j extends l {
    public final kotlinx.collections.immutable.b a;
    public final kotlinx.collections.immutable.b b;

    public j(kotlinx.collections.immutable.b header, kotlinx.collections.immutable.b list) {
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(list, "list");
        this.a = header;
        this.b = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && Intrinsics.b(this.b, jVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Items(header=" + this.a + ", list=" + this.b + ")";
    }
}
