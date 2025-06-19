package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class B1 {
    public final String a;
    public final int b;

    public B1(String suggestion, int i) {
        Intrinsics.checkNotNullParameter(suggestion, "suggestion");
        this.a = suggestion;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B1)) {
            return false;
        }
        B1 b1 = (B1) obj;
        return Intrinsics.b(this.a, b1.a) && this.b == b1.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SearchSuggestion(suggestion=" + this.a + ", rank=" + this.b + ")";
    }
}
