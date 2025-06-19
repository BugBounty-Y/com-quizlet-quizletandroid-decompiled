package assistantMode.types.test;

import androidx.compose.animation.d0;
import assistantMode.types.GradedAnswer$$serializer;
import assistantMode.types.TestGeneratorOutputMetadata;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class GradedTestResult implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {null, new C5048d(GradedAnswer$$serializer.INSTANCE, 0), null};
    public final double a;
    public final List b;
    public final TestGeneratorOutputMetadata c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GradedTestResult$$serializer.INSTANCE;
        }
    }

    public GradedTestResult(double d2, ArrayList gradedAnswers, TestGeneratorOutputMetadata metadata) {
        Intrinsics.checkNotNullParameter(gradedAnswers, "gradedAnswers");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = d2;
        this.b = gradedAnswers;
        this.c = metadata;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GradedTestResult)) {
            return false;
        }
        GradedTestResult gradedTestResult = (GradedTestResult) obj;
        return Double.compare(this.a, gradedTestResult.a) == 0 && Intrinsics.b(this.b, gradedTestResult.b) && Intrinsics.b(this.c, gradedTestResult.c);
    }

    @Override // assistantMode.types.test.a
    public final TestGeneratorOutputMetadata getMetadata() {
        return this.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(Double.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        return "GradedTestResult(gradePercentage=" + this.a + ", gradedAnswers=" + this.b + ", metadata=" + this.c + ")";
    }

    public /* synthetic */ GradedTestResult(int i, double d2, List list, TestGeneratorOutputMetadata testGeneratorOutputMetadata) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, GradedTestResult$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = d2;
        this.b = list;
        if ((i & 4) == 0) {
            this.c = new TestGeneratorOutputMetadata(false, 7);
        } else {
            this.c = testGeneratorOutputMetadata;
        }
    }
}
