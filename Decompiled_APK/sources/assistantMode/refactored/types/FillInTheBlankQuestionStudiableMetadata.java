package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.l;
import assistantMode.refactored.modelTypes.AudioValue;
import assistantMode.refactored.modelTypes.AudioValue$$serializer;
import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.refactored.modelTypes.DiagramShapeValue$$serializer;
import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.refactored.modelTypes.ImageValue$$serializer;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.modelTypes.TextValue$$serializer;
import assistantMode.refactored.modelTypes.VideoValue;
import assistantMode.refactored.modelTypes.VideoValue$$serializer;
import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FillInTheBlankQuestionStudiableMetadata implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] j = {null, null, null, null, null, null, new kotlinx.serialization.e("assistantMode.refactored.modelTypes.MediaValue", K.a(assistantMode.refactored.modelTypes.c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{AudioValue$$serializer.INSTANCE, DiagramShapeValue$$serializer.INSTANCE, ImageValue$$serializer.INSTANCE, TextValue$$serializer.INSTANCE, VideoValue$$serializer.INSTANCE}, new Annotation[0]), new C5048d(FillInTheBlankKeyphraseLocation$$serializer.INSTANCE, 0), null};
    public final long a;
    public final l b;
    public final long c;
    public final j d;
    public final String e;
    public final long f;
    public final assistantMode.refactored.modelTypes.c g;
    public final List h;
    public final m i;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FillInTheBlankQuestionStudiableMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FillInTheBlankQuestionStudiableMetadata(int i, long j2, l lVar, long j3, j jVar, String str, long j4, assistantMode.refactored.modelTypes.c cVar, List list, m mVar) {
        if (255 != (i & 255)) {
            AbstractC5047c0.k(i, 255, FillInTheBlankQuestionStudiableMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j2;
        this.b = lVar;
        this.c = j3;
        this.d = jVar;
        this.e = str;
        this.f = j4;
        this.g = cVar;
        this.h = list;
        if ((i & 256) == 0) {
            this.i = m.c;
        } else {
            this.i = mVar;
        }
    }

    @Override // assistantMode.refactored.types.f
    public final long a() {
        return this.f;
    }

    @Override // assistantMode.refactored.types.f
    public final long b() {
        return this.a;
    }

    @Override // assistantMode.refactored.types.f
    public final String c() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FillInTheBlankQuestionStudiableMetadata)) {
            return false;
        }
        FillInTheBlankQuestionStudiableMetadata fillInTheBlankQuestionStudiableMetadata = (FillInTheBlankQuestionStudiableMetadata) obj;
        return this.a == fillInTheBlankQuestionStudiableMetadata.a && this.b == fillInTheBlankQuestionStudiableMetadata.b && this.c == fillInTheBlankQuestionStudiableMetadata.c && this.d == fillInTheBlankQuestionStudiableMetadata.d && Intrinsics.b(this.e, fillInTheBlankQuestionStudiableMetadata.e) && this.f == fillInTheBlankQuestionStudiableMetadata.f && Intrinsics.b(this.g, fillInTheBlankQuestionStudiableMetadata.g) && Intrinsics.b(this.h, fillInTheBlankQuestionStudiableMetadata.h) && this.i == fillInTheBlankQuestionStudiableMetadata.i;
    }

    public final int hashCode() {
        return this.i.hashCode() + d0.f((this.g.hashCode() + d0.d(d0.e((this.d.hashCode() + d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c)) * 31, 31, this.e), 31, this.f)) * 31, 31, this.h);
    }

    public final String toString() {
        return "FillInTheBlankQuestionStudiableMetadata(studiableItemId=" + this.a + ", studiableItemType=" + this.b + ", studiableContainerId=" + this.c + ", studiableContainerType=" + this.d + ", modelVersion=" + this.e + ", predictionTimestamp=" + this.f + ", keyphrase=" + this.g + ", keyphraseLocations=" + this.h + ", cardSideLabel=" + this.i + ")";
    }
}
