package assistantMode.refactored.types;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class FITBBlankSegment$Companion {
    public static final /* synthetic */ FITBBlankSegment$Companion a = new FITBBlankSegment$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.refactored.types.FITBBlankSegment", K.a(a.class), new kotlin.reflect.c[]{K.a(FITBMCQBlankSegment.class), K.a(FITBWrittenBlankSegment.class)}, new KSerializer[]{FITBMCQBlankSegment$$serializer.INSTANCE, FITBWrittenBlankSegment$$serializer.INSTANCE}, new Annotation[0]);
    }
}
