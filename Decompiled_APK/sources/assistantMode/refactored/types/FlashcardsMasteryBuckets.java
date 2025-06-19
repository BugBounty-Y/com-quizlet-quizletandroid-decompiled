package assistantMode.refactored.types;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.P;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsMasteryBuckets implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c;
    public final List a;
    public final List b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsMasteryBuckets$$serializer.INSTANCE;
        }
    }

    static {
        P p = P.a;
        c = new KSerializer[]{new C5048d(p, 0), new C5048d(p, 0)};
    }

    public /* synthetic */ FlashcardsMasteryBuckets(int i, List list, List list2) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, FlashcardsMasteryBuckets$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsMasteryBuckets)) {
            return false;
        }
        FlashcardsMasteryBuckets flashcardsMasteryBuckets = (FlashcardsMasteryBuckets) obj;
        return Intrinsics.b(this.a, flashcardsMasteryBuckets.a) && Intrinsics.b(this.b, flashcardsMasteryBuckets.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FlashcardsMasteryBuckets(remaining=" + this.a + ", completed=" + this.b + ")";
    }

    public FlashcardsMasteryBuckets(List remaining, List completed) {
        Intrinsics.checkNotNullParameter(remaining, "remaining");
        Intrinsics.checkNotNullParameter(completed, "completed");
        this.a = remaining;
        this.b = completed;
    }
}
