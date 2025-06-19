package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
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
public final class CardSide {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {null, null, new C5048d(new e("assistantMode.refactored.modelTypes.MediaValue", K.a(c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{AudioValue$$serializer.INSTANCE, DiagramShapeValue$$serializer.INSTANCE, ImageValue$$serializer.INSTANCE, TextValue$$serializer.INSTANCE, VideoValue$$serializer.INSTANCE}, new Annotation[0]), 0), new C5048d(CardSideDistractor$$serializer.INSTANCE, 0)};
    public final long a;
    public final m b;
    public final List c;
    public final List d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CardSide$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ CardSide(int i, long j, m mVar, List list, List list2) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, CardSide$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = mVar;
        this.c = list;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = list2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CardSide)) {
            return false;
        }
        CardSide cardSide = (CardSide) obj;
        return this.a == cardSide.a && this.b == cardSide.b && Intrinsics.b(this.c, cardSide.c) && Intrinsics.b(this.d, cardSide.d);
    }

    public final int hashCode() {
        int iF = d0.f(assistantMode.refactored.a.e(this.b, Long.hashCode(this.a) * 31, 31), 31, this.c);
        List list = this.d;
        return iF + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        return "CardSide(sideId=" + this.a + ", label=" + this.b + ", media=" + this.c + ", distractors=" + this.d + ")";
    }

    public CardSide(long j, m label, ArrayList media, ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(media, "media");
        this.a = j;
        this.b = label;
        this.c = media;
        this.d = arrayList;
    }
}
