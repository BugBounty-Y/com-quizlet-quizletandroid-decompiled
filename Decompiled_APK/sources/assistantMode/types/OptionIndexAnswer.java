package assistantMode.types;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class OptionIndexAnswer extends C {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return OptionIndexAnswer$$serializer.INSTANCE;
        }
    }

    public OptionIndexAnswer(int i, long j) {
        if (1 == (i & 1)) {
            this.a = j;
        } else {
            AbstractC5047c0.k(i, 1, OptionIndexAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof OptionIndexAnswer) && this.a == ((OptionIndexAnswer) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("OptionIndexAnswer(value="));
    }

    public OptionIndexAnswer(long j) {
        this.a = j;
    }
}
