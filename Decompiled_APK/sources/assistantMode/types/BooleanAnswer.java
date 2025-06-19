package assistantMode.types;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class BooleanAnswer extends v {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return BooleanAnswer$$serializer.INSTANCE;
        }
    }

    public BooleanAnswer(int i, boolean z) {
        if (1 == (i & 1)) {
            this.a = z;
        } else {
            AbstractC5047c0.k(i, 1, BooleanAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BooleanAnswer) && this.a == ((BooleanAnswer) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("BooleanAnswer(value="), this.a);
    }

    public BooleanAnswer(boolean z) {
        this.a = z;
    }
}
