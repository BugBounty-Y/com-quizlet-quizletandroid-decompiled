package assistantMode.types;

import com.quizlet.shared.models.api.metering.MeteredEvent$$serializer;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class PaywallMetadata implements F {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new kotlinx.serialization.internal.F(com.quizlet.shared.enums.g.f, MeteredEvent$$serializer.INSTANCE, 1)};
    public Map a = null;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return PaywallMetadata$$serializer.INSTANCE;
        }
    }

    @Override // assistantMode.types.F
    public final void a(LinkedHashMap linkedHashMap) {
        this.a = linkedHashMap;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof PaywallMetadata) && Intrinsics.b(this.a, ((PaywallMetadata) obj).a);
    }

    public final int hashCode() {
        Map map = this.a;
        if (map == null) {
            return 0;
        }
        return map.hashCode();
    }

    public final String toString() {
        return "PaywallMetadata(meteringData=" + this.a + ")";
    }
}
