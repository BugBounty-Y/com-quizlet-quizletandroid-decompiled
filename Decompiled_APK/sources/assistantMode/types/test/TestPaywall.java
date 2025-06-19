package assistantMode.types.test;

import assistantMode.types.TestGeneratorOutputMetadata;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class TestPaywall implements b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final TestGeneratorOutputMetadata a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TestPaywall$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TestPaywall(int i, TestGeneratorOutputMetadata testGeneratorOutputMetadata) {
        if ((i & 1) == 0) {
            this.a = new TestGeneratorOutputMetadata(false, 7);
        } else {
            this.a = testGeneratorOutputMetadata;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof TestPaywall) && Intrinsics.b(this.a, ((TestPaywall) obj).a);
    }

    @Override // assistantMode.types.test.a
    public final TestGeneratorOutputMetadata getMetadata() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TestPaywall(metadata=" + this.a + ")";
    }

    public TestPaywall(TestGeneratorOutputMetadata metadata) {
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = metadata;
    }
}
