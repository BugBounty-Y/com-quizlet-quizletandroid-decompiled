package assistantMode.types.unions;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class MediaAttribute$Companion {
    public static final /* synthetic */ MediaAttribute$Companion a = new MediaAttribute$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("assistantMode.types.unions.MediaAttribute", K.a(a.class), new c[]{K.a(AudioAttribute.class), K.a(ImageAttribute.class), K.a(LocationAttribute.class), K.a(TextAttribute.class), K.a(VideoAttribute.class)}, new KSerializer[]{AudioAttribute$$serializer.INSTANCE, ImageAttribute$$serializer.INSTANCE, LocationAttribute$$serializer.INSTANCE, TextAttribute$$serializer.INSTANCE, VideoAttribute$$serializer.INSTANCE}, new Annotation[0]);
    }
}
