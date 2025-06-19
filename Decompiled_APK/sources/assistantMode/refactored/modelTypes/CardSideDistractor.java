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
public final class CardSideDistractor {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", K.a(c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{AudioValue$$serializer.INSTANCE, DiagramShapeValue$$serializer.INSTANCE, ImageValue$$serializer.INSTANCE, TextValue$$serializer.INSTANCE, VideoValue$$serializer.INSTANCE}, new Annotation[0]), 0)};
    public final List a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CardSideDistractor$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ CardSideDistractor(int i, List list) {
        if (1 == (i & 1)) {
            this.a = list;
        } else {
            AbstractC5047c0.k(i, 1, CardSideDistractor$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof CardSideDistractor) && Intrinsics.b(this.a, ((CardSideDistractor) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("CardSideDistractor(media="), this.a);
    }

    public CardSideDistractor(List media) {
        Intrinsics.checkNotNullParameter(media, "media");
        this.a = media;
    }
}
