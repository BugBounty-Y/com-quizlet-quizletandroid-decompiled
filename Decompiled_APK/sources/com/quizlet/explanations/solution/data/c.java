package com.quizlet.explanations.solution.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.X;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends d {
    public final X c;
    public final List d;
    public final h e;
    public final boolean f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(X meteringInfo, List solutions, h metadata, boolean z) {
        super(solutions, z);
        Intrinsics.checkNotNullParameter(meteringInfo, "meteringInfo");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.c = meteringInfo;
        this.d = solutions;
        this.e = metadata;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.c, cVar.c) && this.d.equals(cVar.d) && this.e.equals(cVar.e) && this.f == cVar.f;
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final com.google.mlkit.common.model.a getMetadata() {
        return this.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + ((this.e.hashCode() + d0.f(this.c.hashCode() * 31, 31, this.d)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Question(meteringInfo=");
        sb.append(this.c);
        sb.append(", solutions=");
        sb.append(this.d);
        sb.append(", metadata=");
        sb.append(this.e);
        sb.append(", blurringSolutionsFeatureEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
