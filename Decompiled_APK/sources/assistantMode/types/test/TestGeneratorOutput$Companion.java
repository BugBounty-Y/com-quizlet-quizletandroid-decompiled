package assistantMode.types.test;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class TestGeneratorOutput$Companion {
    public static final /* synthetic */ TestGeneratorOutput$Companion a = new TestGeneratorOutput$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("assistantMode.types.test.TestGeneratorOutput", K.a(a.class), new c[]{K.a(GradedTestResult.class), K.a(Test.class), K.a(TestPaywall.class)}, new KSerializer[]{GradedTestResult$$serializer.INSTANCE, Test$$serializer.INSTANCE, TestPaywall$$serializer.INSTANCE}, new Annotation[0]);
    }
}
