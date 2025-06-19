package assistantMode.types.test;

import assistantMode.refactored.types.d;
import assistantMode.types.TestGeneratorOutputMetadata;
import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.c;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class Test implements b {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(new c(K.a(d.class), new Annotation[0]), 0), null};
    public final List a;
    public final TestGeneratorOutputMetadata b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Test$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Test(int i, List list, TestGeneratorOutputMetadata testGeneratorOutputMetadata) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, Test$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        if ((i & 2) == 0) {
            this.b = new TestGeneratorOutputMetadata(false, 7);
        } else {
            this.b = testGeneratorOutputMetadata;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Test)) {
            return false;
        }
        Test test2 = (Test) obj;
        return Intrinsics.b(this.a, test2.a) && Intrinsics.b(this.b, test2.b);
    }

    @Override // assistantMode.types.test.a
    public final TestGeneratorOutputMetadata getMetadata() {
        return this.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Test(questions=" + this.a + ", metadata=" + this.b + ")";
    }

    public Test(List questions, TestGeneratorOutputMetadata metadata) {
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = questions;
        this.b = metadata;
    }
}
