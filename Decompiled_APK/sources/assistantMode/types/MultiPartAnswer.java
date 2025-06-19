package assistantMode.types;

import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.K;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class MultiPartAnswer extends v {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b;
    public final Map a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MultiPartAnswer$$serializer.INSTANCE;
        }
    }

    static {
        K k = K.a;
        b = new KSerializer[]{new kotlinx.serialization.internal.F(k, k, 1)};
    }

    public MultiPartAnswer(int i, Map map) {
        if (1 == (i & 1)) {
            this.a = map;
        } else {
            AbstractC5047c0.k(i, 1, MultiPartAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof MultiPartAnswer) && Intrinsics.b(this.a, ((MultiPartAnswer) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MultiPartAnswer(value=" + this.a + ")";
    }

    public MultiPartAnswer(LinkedHashMap value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
    }
}
