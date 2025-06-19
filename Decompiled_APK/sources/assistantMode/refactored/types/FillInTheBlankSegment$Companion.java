package assistantMode.refactored.types;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class FillInTheBlankSegment$Companion {
    public static final /* synthetic */ FillInTheBlankSegment$Companion a = new FillInTheBlankSegment$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.refactored.types.FillInTheBlankSegment", K.a(b.class), new kotlin.reflect.c[]{K.a(FITBMCQBlankSegment.class), K.a(FITBWrittenBlankSegment.class), K.a(FITBTextSegment.class)}, new KSerializer[]{FITBMCQBlankSegment$$serializer.INSTANCE, FITBWrittenBlankSegment$$serializer.INSTANCE, FITBTextSegment$$serializer.INSTANCE}, new Annotation[0]);
    }
}
