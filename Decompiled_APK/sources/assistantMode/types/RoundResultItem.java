package assistantMode.types;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class RoundResultItem {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final boolean b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RoundResultItem$$serializer.INSTANCE;
        }
    }

    public RoundResultItem(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RoundResultItem)) {
            return false;
        }
        RoundResultItem roundResultItem = (RoundResultItem) obj;
        return this.a == roundResultItem.a && this.b == roundResultItem.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "RoundResultItem(studiableItemId=" + this.a + ", isCorrect=" + this.b + ")";
    }

    public /* synthetic */ RoundResultItem(boolean z, long j, int i) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, RoundResultItem$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = z;
    }
}
