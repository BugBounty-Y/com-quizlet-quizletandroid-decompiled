package assistantMode.refactored.modelTypes;

import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class ParsedMultipleChoiceOption {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", K.a(c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{AudioValue$$serializer.INSTANCE, DiagramShapeValue$$serializer.INSTANCE, ImageValue$$serializer.INSTANCE, TextValue$$serializer.INSTANCE, VideoValue$$serializer.INSTANCE}, new Annotation[0]), 0), null};
    public final List a;
    public final boolean b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ParsedMultipleChoiceOption$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ParsedMultipleChoiceOption(boolean z, int i, List list) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, ParsedMultipleChoiceOption$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ParsedMultipleChoiceOption)) {
            return false;
        }
        ParsedMultipleChoiceOption parsedMultipleChoiceOption = (ParsedMultipleChoiceOption) obj;
        return Intrinsics.b(this.a, parsedMultipleChoiceOption.a) && this.b == parsedMultipleChoiceOption.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ParsedMultipleChoiceOption(media=" + this.a + ", isCorrect=" + this.b + ")";
    }
}
