package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.C4950i;
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
public final class MultipleChoiceOption {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f;
    public final long a;
    public final boolean b;
    public final Integer c;
    public final List d;
    public final List e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MultipleChoiceOption$$serializer.INSTANCE;
        }
    }

    static {
        C4950i c4950iA = K.a(c.class);
        kotlin.reflect.c[] cVarArr = {K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)};
        AudioValue$$serializer audioValue$$serializer = AudioValue$$serializer.INSTANCE;
        DiagramShapeValue$$serializer diagramShapeValue$$serializer = DiagramShapeValue$$serializer.INSTANCE;
        ImageValue$$serializer imageValue$$serializer = ImageValue$$serializer.INSTANCE;
        TextValue$$serializer textValue$$serializer = TextValue$$serializer.INSTANCE;
        VideoValue$$serializer videoValue$$serializer = VideoValue$$serializer.INSTANCE;
        f = new KSerializer[]{null, null, null, new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", c4950iA, cVarArr, new KSerializer[]{audioValue$$serializer, diagramShapeValue$$serializer, imageValue$$serializer, textValue$$serializer, videoValue$$serializer}, new Annotation[0]), 0), new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", K.a(c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{audioValue$$serializer, diagramShapeValue$$serializer, imageValue$$serializer, textValue$$serializer, videoValue$$serializer}, new Annotation[0]), 0)};
    }

    public /* synthetic */ MultipleChoiceOption(int i, long j, boolean z, Integer num, List list, List list2) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, MultipleChoiceOption$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = z;
        this.c = num;
        this.d = list;
        this.e = list2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MultipleChoiceOption)) {
            return false;
        }
        MultipleChoiceOption multipleChoiceOption = (MultipleChoiceOption) obj;
        return this.a == multipleChoiceOption.a && this.b == multipleChoiceOption.b && Intrinsics.b(this.c, multipleChoiceOption.c) && Intrinsics.b(this.d, multipleChoiceOption.d) && Intrinsics.b(this.e, multipleChoiceOption.e);
    }

    public final int hashCode() {
        int iG = d0.g(Long.hashCode(this.a) * 31, 31, this.b);
        Integer num = this.c;
        return this.e.hashCode() + d0.f((iG + (num == null ? 0 : num.hashCode())) * 31, 31, this.d);
    }

    public final String toString() {
        return "MultipleChoiceOption(optionId=" + this.a + ", isCorrect=" + this.b + ", rank=" + this.c + ", optionMedia=" + this.d + ", explanationMedia=" + this.e + ")";
    }
}
