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
public final class TestOrPaywall$Companion {
    public static final /* synthetic */ TestOrPaywall$Companion a = new TestOrPaywall$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("assistantMode.types.test.TestOrPaywall", K.a(b.class), new c[]{K.a(Test.class), K.a(TestPaywall.class)}, new KSerializer[]{Test$$serializer.INSTANCE, TestPaywall$$serializer.INSTANCE}, new Annotation[0]);
    }
}
