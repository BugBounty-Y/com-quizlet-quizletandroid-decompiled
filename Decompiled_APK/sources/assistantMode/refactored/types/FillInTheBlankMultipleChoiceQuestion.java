package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.types.F;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
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
public final class FillInTheBlankMultipleChoiceQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, new C5048d(new kotlinx.serialization.e("assistantMode.refactored.types.FillInTheBlankSegment", K.a(b.class), new kotlin.reflect.c[]{K.a(FITBMCQBlankSegment.class), K.a(FITBWrittenBlankSegment.class), K.a(FITBTextSegment.class)}, new KSerializer[]{FITBMCQBlankSegment$$serializer.INSTANCE, FITBWrittenBlankSegment$$serializer.INSTANCE, FITBTextSegment$$serializer.INSTANCE}, new Annotation[0]), 0), null, null, null};
    public final QuestionElement a;
    public final List b;
    public final boolean c;
    public final QuestionMetadata d;
    public final k e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FillInTheBlankMultipleChoiceQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FillInTheBlankMultipleChoiceQuestion(int i, QuestionElement questionElement, List list, boolean z, QuestionMetadata questionMetadata, k kVar) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, FillInTheBlankMultipleChoiceQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = list;
        this.c = z;
        this.d = questionMetadata;
        if ((i & 16) == 0) {
            this.e = k.n;
        } else {
            this.e = kVar;
        }
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FillInTheBlankMultipleChoiceQuestion)) {
            return false;
        }
        FillInTheBlankMultipleChoiceQuestion fillInTheBlankMultipleChoiceQuestion = (FillInTheBlankMultipleChoiceQuestion) obj;
        return Intrinsics.b(this.a, fillInTheBlankMultipleChoiceQuestion.a) && Intrinsics.b(this.b, fillInTheBlankMultipleChoiceQuestion.b) && this.c == fillInTheBlankMultipleChoiceQuestion.c && Intrinsics.b(this.d, fillInTheBlankMultipleChoiceQuestion.d);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.d;
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g(d0.f(this.a.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "FillInTheBlankMultipleChoiceQuestion(prompt=" + this.a + ", segments=" + this.b + ", isMulti=" + this.c + ", metadata=" + this.d + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.d;
    }

    public FillInTheBlankMultipleChoiceQuestion(QuestionElement prompt, ArrayList segments, boolean z, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(segments, "segments");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompt;
        this.b = segments;
        this.c = z;
        this.d = metadata;
        this.e = k.n;
    }
}
