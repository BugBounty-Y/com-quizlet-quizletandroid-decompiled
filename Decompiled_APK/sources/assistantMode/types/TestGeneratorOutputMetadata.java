package assistantMode.types;

import androidx.compose.animation.d0;
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
public final class TestGeneratorOutputMetadata implements F {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {null, null, new kotlinx.serialization.internal.F(com.quizlet.shared.enums.g.f, MeteredEvent$$serializer.INSTANCE, 1)};
    public final boolean a;
    public final boolean b;
    public Map c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TestGeneratorOutputMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TestGeneratorOutputMetadata(int i, boolean z, boolean z2, Map map) {
        if ((i & 1) == 0) {
            this.a = false;
        } else {
            this.a = z;
        }
        if ((i & 2) == 0) {
            this.b = false;
        } else {
            this.b = z2;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = map;
        }
    }

    @Override // assistantMode.types.F
    public final void a(LinkedHashMap linkedHashMap) {
        this.c = linkedHashMap;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TestGeneratorOutputMetadata)) {
            return false;
        }
        TestGeneratorOutputMetadata testGeneratorOutputMetadata = (TestGeneratorOutputMetadata) obj;
        return this.a == testGeneratorOutputMetadata.a && this.b == testGeneratorOutputMetadata.b && Intrinsics.b(this.c, testGeneratorOutputMetadata.c);
    }

    public final int hashCode() {
        int iG = d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
        Map map = this.c;
        return iG + (map == null ? 0 : map.hashCode());
    }

    public final String toString() {
        return "TestGeneratorOutputMetadata(isRetriedTest=" + this.a + ", shouldPaywallRetriedTest=" + this.b + ", meteringData=" + this.c + ")";
    }

    public TestGeneratorOutputMetadata(boolean z, int i) {
        this.a = (i & 1) != 0 ? false : z;
        this.b = false;
        this.c = null;
    }
}
