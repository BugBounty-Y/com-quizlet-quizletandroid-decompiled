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
public final class MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] l;
    public final long a;
    public final l b;
    public final long c;
    public final j d;
    public final String e;
    public final long f;
    public final assistantMode.refactored.modelTypes.c g;
    public final List h;
    public final List i;
    public final m j;
    public final m k;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata$$serializer.INSTANCE;
        }
    }

    static {
        kotlinx.serialization.e eVar = new kotlinx.serialization.e("assistantMode.refactored.modelTypes.MediaValue", K.a(assistantMode.refactored.modelTypes.c.class), new kotlin.reflect.c[]{K.a(AudioValue.class), K.a(DiagramShapeValue.class), K.a(ImageValue.class), K.a(TextValue.class), K.a(VideoValue.class)}, new KSerializer[]{AudioValue$$serializer.INSTANCE, DiagramShapeValue$$serializer.INSTANCE, ImageValue$$serializer.INSTANCE, TextValue$$serializer.INSTANCE, VideoValue$$serializer.INSTANCE}, new Annotation[0]);
        CardSideDistractor$$serializer cardSideDistractor$$serializer = CardSideDistractor$$serializer.INSTANCE;
        l = new KSerializer[]{null, null, null, null, null, null, eVar, new C5048d(cardSideDistractor$$serializer, 0), new C5048d(cardSideDistractor$$serializer, 0), null, null};
    }

    public /* synthetic */ MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata(int i, long j, l lVar, long j2, j jVar, String str, long j3, assistantMode.refactored.modelTypes.c cVar, List list, List list2, m mVar, m mVar2) {
        if (2047 != (i & 2047)) {
            AbstractC5047c0.k(i, 2047, MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = lVar;
        this.c = j2;
        this.d = jVar;
        this.e = str;
        this.f = j3;
        this.g = cVar;
        this.h = list;
        this.i = list2;
        this.j = mVar;
        this.k = mVar2;
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
        if (!(obj instanceof MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata)) {
            return false;
        }
        MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata multipleChoiceSelectAllThatApplyQuestionStudiableMetadata = (MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata) obj;
        return this.a == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.a && this.b == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.b && this.c == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.c && this.d == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.d && Intrinsics.b(this.e, multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.e) && this.f == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.f && Intrinsics.b(this.g, multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.g) && Intrinsics.b(this.h, multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.h) && Intrinsics.b(this.i, multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.i) && this.j == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.j && this.k == multipleChoiceSelectAllThatApplyQuestionStudiableMetadata.k;
    }

    public final int hashCode() {
        return this.k.hashCode() + assistantMode.refactored.a.e(this.j, d0.f(d0.f((this.g.hashCode() + d0.d(d0.e((this.d.hashCode() + d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c)) * 31, 31, this.e), 31, this.f)) * 31, 31, this.h), 31, this.i), 31);
    }

    public final String toString() {
        return "MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata(studiableItemId=" + this.a + ", studiableItemType=" + this.b + ", studiableContainerId=" + this.c + ", studiableContainerType=" + this.d + ", modelVersion=" + this.e + ", predictionTimestamp=" + this.f + ", prompt=" + this.g + ", listItems=" + this.h + ", distractors=" + this.i + ", answerSide=" + this.j + ", promptSide=" + this.k + ")";
    }
}
