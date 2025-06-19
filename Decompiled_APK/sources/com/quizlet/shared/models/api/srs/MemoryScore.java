package com.quizlet.shared.models.api.srs;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class MemoryScore {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final long b;
    public final com.quizlet.shared.enums.f c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MemoryScore$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ MemoryScore(int i, long j, long j2, com.quizlet.shared.enums.f fVar) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, MemoryScore$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
        this.c = fVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MemoryScore)) {
            return false;
        }
        MemoryScore memoryScore = (MemoryScore) obj;
        return this.a == memoryScore.a && this.b == memoryScore.b && this.c == memoryScore.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        return "MemoryScore(delay=" + this.a + ", score=" + this.b + ", label=" + this.c + ")";
    }
}
