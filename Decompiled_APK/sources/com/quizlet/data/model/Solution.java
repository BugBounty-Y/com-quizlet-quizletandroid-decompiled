package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Solution {
    public final List a;
    public final int b;

    public Solution(List steps, int i) {
        Intrinsics.checkNotNullParameter(steps, "steps");
        this.a = steps;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Solution)) {
            return false;
        }
        Solution solution = (Solution) obj;
        return Intrinsics.b(this.a, solution.a) && this.b == solution.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Solution(steps=" + this.a + ", totalSteps=" + this.b + ")";
    }
}
