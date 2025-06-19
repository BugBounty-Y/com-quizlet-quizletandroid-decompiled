package com.quizlet.explanations.solution.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements i {
    public final List a;
    public final com.google.mlkit.common.model.a b;

    public f(List list, com.google.mlkit.common.model.a metadata) {
        Intrinsics.checkNotNullParameter(list, "list");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = list;
        this.b = metadata;
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final List b() {
        return this.a;
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final boolean c() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b);
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final com.google.mlkit.common.model.a getMetadata() {
        return this.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SolutionData(list=" + this.a + ", metadata=" + this.b + ")";
    }
}
