package assistantMode.refactored.types;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class TotalProgress {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new kotlinx.serialization.c(K.a(c.class), new Annotation[0]), null};
    public final c a;
    public final double b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TotalProgress$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TotalProgress(int i, c cVar, double d) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, TotalProgress$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = cVar;
        this.b = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TotalProgress)) {
            return false;
        }
        TotalProgress totalProgress = (TotalProgress) obj;
        return Intrinsics.b(this.a, totalProgress.a) && Double.compare(this.b, totalProgress.b) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "TotalProgress(masteryBuckets=" + this.a + ", studyProgress=" + this.b + ")";
    }

    public TotalProgress(c masteryBuckets, double d) {
        Intrinsics.checkNotNullParameter(masteryBuckets, "masteryBuckets");
        this.a = masteryBuckets;
        this.b = d;
    }
}
