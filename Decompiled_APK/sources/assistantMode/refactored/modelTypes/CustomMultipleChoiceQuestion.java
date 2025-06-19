package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.j;
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
public final class CustomMultipleChoiceQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] h;
    public final long a;
    public final long b;
    public final j c;
    public final long d;
    public final List e;
    public final List f;
    public final List g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CustomMultipleChoiceQuestion$$serializer.INSTANCE;
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
        h = new KSerializer[]{null, null, null, null, new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", c4950iA, cVarArr, new KSerializer[]{audioValue$$serializer, diagramShapeValue$$serializer, imageValue$$serializer, textValue$$serializer, videoValue$$serializer}, new Annotation[0]), 0), new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", K.a(c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{audioValue$$serializer, diagramShapeValue$$serializer, imageValue$$serializer, textValue$$serializer, videoValue$$serializer}, new Annotation[0]), 0), new C5048d(MultipleChoiceOption$$serializer.INSTANCE, 0)};
    }

    public /* synthetic */ CustomMultipleChoiceQuestion(int i, long j, long j2, j jVar, long j3, List list, List list2, List list3) {
        if (127 != (i & 127)) {
            AbstractC5047c0.k(i, 127, CustomMultipleChoiceQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
        this.c = jVar;
        this.d = j3;
        this.e = list;
        this.f = list2;
        this.g = list3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CustomMultipleChoiceQuestion)) {
            return false;
        }
        CustomMultipleChoiceQuestion customMultipleChoiceQuestion = (CustomMultipleChoiceQuestion) obj;
        return this.a == customMultipleChoiceQuestion.a && this.b == customMultipleChoiceQuestion.b && this.c == customMultipleChoiceQuestion.c && this.d == customMultipleChoiceQuestion.d && Intrinsics.b(this.e, customMultipleChoiceQuestion.e) && Intrinsics.b(this.f, customMultipleChoiceQuestion.f) && Intrinsics.b(this.g, customMultipleChoiceQuestion.g);
    }

    @Override // assistantMode.refactored.modelTypes.d
    public final long getId() {
        return this.a;
    }

    public final int hashCode() {
        return this.g.hashCode() + d0.f(d0.f(d0.d((this.c.hashCode() + d0.d(Long.hashCode(this.a) * 31, 31, this.b)) * 31, 31, this.d), 31, this.e), 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CustomMultipleChoiceQuestion(id=");
        sb.append(this.a);
        sb.append(", studiableContainerId=");
        sb.append(this.b);
        sb.append(", studiableContainerType=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", promptMedia=");
        sb.append(this.e);
        sb.append(", hintMedia=");
        sb.append(this.f);
        sb.append(", options=");
        return android.support.v4.media.session.a.n(")", sb, this.g);
    }
}
