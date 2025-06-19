package com.quizlet.explanations.solution.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends d {
    public final List c;
    public final g d;
    public final boolean e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(List solutions, g metadata, boolean z) {
        super(solutions, z);
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.c = solutions;
        this.d = metadata;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.c, bVar.c) && this.d.equals(bVar.d) && this.e == bVar.e;
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final com.google.mlkit.common.model.a getMetadata() {
        return this.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + ((this.d.hashCode() + (this.c.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Exercise(solutions=");
        sb.append(this.c);
        sb.append(", metadata=");
        sb.append(this.d);
        sb.append(", blurringSolutionsFeatureEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
