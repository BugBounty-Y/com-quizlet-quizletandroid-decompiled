package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.l;
import assistantMode.refactored.modelTypes.AudioValue;
import assistantMode.refactored.modelTypes.AudioValue$$serializer;
import assistantMode.refactored.modelTypes.CardSideDistractor$$serializer;
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
public final class FillInTheBlankMultipleChoiceQuestionStudiableMetadata implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] k = {null, null, null, null, null, null, new kotlinx.serialization.e("assistantMode.refactored.modelTypes.MediaValue", K.a(assistantMode.refactored.modelTypes.c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{AudioValue$$serializer.INSTANCE, DiagramShapeValue$$serializer.INSTANCE, ImageValue$$serializer.INSTANCE, TextValue$$serializer.INSTANCE, VideoValue$$serializer.INSTANCE}, new Annotation[0]), null, null, new C5048d(CardSideDistractor$$serializer.INSTANCE, 0)};
    public final long a;
    public final l b;
    public final long c;
    public final j d;
    public final String e;
    public final long f;
    public final assistantMode.refactored.modelTypes.c g;
    public final FillInTheBlankKeyphraseLocation h;
    public final m i;
    public final List j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FillInTheBlankMultipleChoiceQuestionStudiableMetadata(int i, long j, l lVar, long j2, j jVar, String str, long j3, assistantMode.refactored.modelTypes.c cVar, FillInTheBlankKeyphraseLocation fillInTheBlankKeyphraseLocation, m mVar, List list) {
        if (767 != (i & 767)) {
            AbstractC5047c0.k(i, 767, FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = lVar;
        this.c = j2;
        this.d = jVar;
        this.e = str;
        this.f = j3;
        this.g = cVar;
        this.h = fillInTheBlankKeyphraseLocation;
        if ((i & 256) == 0) {
            this.i = m.c;
        } else {
            this.i = mVar;
        }
        this.j = list;
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
        if (!(obj instanceof FillInTheBlankMultipleChoiceQuestionStudiableMetadata)) {
            return false;
        }
        FillInTheBlankMultipleChoiceQuestionStudiableMetadata fillInTheBlankMultipleChoiceQuestionStudiableMetadata = (FillInTheBlankMultipleChoiceQuestionStudiableMetadata) obj;
        return this.a == fillInTheBlankMultipleChoiceQuestionStudiableMetadata.a && this.b == fillInTheBlankMultipleChoiceQuestionStudiableMetadata.b && this.c == fillInTheBlankMultipleChoiceQuestionStudiableMetadata.c && this.d == fillInTheBlankMultipleChoiceQuestionStudiableMetadata.d && Intrinsics.b(this.e, fillInTheBlankMultipleChoiceQuestionStudiableMetadata.e) && this.f == fillInTheBlankMultipleChoiceQuestionStudiableMetadata.f && Intrinsics.b(this.g, fillInTheBlankMultipleChoiceQuestionStudiableMetadata.g) && Intrinsics.b(this.h, fillInTheBlankMultipleChoiceQuestionStudiableMetadata.h) && this.i == fillInTheBlankMultipleChoiceQuestionStudiableMetadata.i && Intrinsics.b(this.j, fillInTheBlankMultipleChoiceQuestionStudiableMetadata.j);
    }

    public final int hashCode() {
        return this.j.hashCode() + assistantMode.refactored.a.e(this.i, (this.h.hashCode() + ((this.g.hashCode() + d0.d(d0.e((this.d.hashCode() + d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c)) * 31, 31, this.e), 31, this.f)) * 31)) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FillInTheBlankMultipleChoiceQuestionStudiableMetadata(studiableItemId=");
        sb.append(this.a);
        sb.append(", studiableItemType=");
        sb.append(this.b);
        sb.append(", studiableContainerId=");
        sb.append(this.c);
        sb.append(", studiableContainerType=");
        sb.append(this.d);
        sb.append(", modelVersion=");
        sb.append(this.e);
        sb.append(", predictionTimestamp=");
        sb.append(this.f);
        sb.append(", keyphrase=");
        sb.append(this.g);
        sb.append(", keyphraseLocation=");
        sb.append(this.h);
        sb.append(", cardSideLabel=");
        sb.append(this.i);
        sb.append(", distractors=");
        return android.support.v4.media.session.a.n(")", sb, this.j);
    }
}
