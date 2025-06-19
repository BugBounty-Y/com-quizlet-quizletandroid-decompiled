package com.quizlet.data.repository.progress;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.G1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final long a;
    public final long b;
    public final G1 c;

    public c(long j, long j2, G1 containerType) {
        Intrinsics.checkNotNullParameter(containerType, "containerType");
        this.a = j;
        this.b = j2;
        this.c = containerType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b && this.c == cVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        return "ProgressResetId(personId=" + this.a + ", containerId=" + this.b + ", containerType=" + this.c + ")";
    }
}
