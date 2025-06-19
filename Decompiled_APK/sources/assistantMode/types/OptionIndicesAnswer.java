package assistantMode.types;

import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.K;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class OptionIndicesAnswer extends C {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new C5048d(K.a, 2)};
    public final Set a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return OptionIndicesAnswer$$serializer.INSTANCE;
        }
    }

    public OptionIndicesAnswer(int i, Set set) {
        if (1 == (i & 1)) {
            this.a = set;
        } else {
            AbstractC5047c0.k(i, 1, OptionIndicesAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof OptionIndicesAnswer) && Intrinsics.b(this.a, ((OptionIndicesAnswer) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "OptionIndicesAnswer(value=" + this.a + ")";
    }

    public OptionIndicesAnswer(Set value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
    }
}
