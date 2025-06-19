package assistantMode.types;

import com.quizlet.shared.models.api.metering.MeteredEvent$$serializer;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.L;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsStepMetadata implements F {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {null, new kotlinx.serialization.internal.F(com.quizlet.shared.enums.g.f, MeteredEvent$$serializer.INSTANCE, 1)};
    public final boolean a;
    public Map b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsStepMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardsStepMetadata(int i, boolean z, Map map) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, FlashcardsStepMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = z;
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = map;
        }
    }

    @Override // assistantMode.types.F
    public final void a(LinkedHashMap linkedHashMap) {
        this.b = linkedHashMap;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsStepMetadata)) {
            return false;
        }
        FlashcardsStepMetadata flashcardsStepMetadata = (FlashcardsStepMetadata) obj;
        return this.a == flashcardsStepMetadata.a && Intrinsics.b(this.b, flashcardsStepMetadata.b);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        Map map = this.b;
        return iHashCode + (map == null ? 0 : map.hashCode());
    }

    public final String toString() {
        return "FlashcardsStepMetadata(isSortingEnabled=" + this.a + ", meteringData=" + this.b + ")";
    }

    public FlashcardsStepMetadata(boolean z, L l) {
        this.a = z;
        this.b = l;
    }
}
