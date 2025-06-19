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
public final class FillInTheBlankQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] g = {null, new C5048d(new kotlinx.serialization.e("assistantMode.refactored.types.FillInTheBlankSegment", K.a(b.class), new kotlin.reflect.c[]{K.a(FITBMCQBlankSegment.class), K.a(FITBWrittenBlankSegment.class), K.a(FITBTextSegment.class)}, new KSerializer[]{FITBMCQBlankSegment$$serializer.INSTANCE, FITBWrittenBlankSegment$$serializer.INSTANCE, FITBTextSegment$$serializer.INSTANCE}, new Annotation[0]), 0), null, null, null, null};
    public final QuestionElement a;
    public final List b;
    public final QuestionMetadata c;
    public final String d;
    public final String e;
    public final k f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FillInTheBlankQuestion$$serializer.INSTANCE;
        }
    }

    public FillInTheBlankQuestion(QuestionElement prompt, ArrayList segments, QuestionMetadata metadata, String modelVersion) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(segments, "segments");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        Intrinsics.checkNotNullParameter(modelVersion, "modelVersion");
        this.a = prompt;
        this.b = segments;
        this.c = metadata;
        this.d = modelVersion;
        this.e = null;
        this.f = k.l;
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FillInTheBlankQuestion)) {
            return false;
        }
        FillInTheBlankQuestion fillInTheBlankQuestion = (FillInTheBlankQuestion) obj;
        return Intrinsics.b(this.a, fillInTheBlankQuestion.a) && Intrinsics.b(this.b, fillInTheBlankQuestion.b) && Intrinsics.b(this.c, fillInTheBlankQuestion.c) && Intrinsics.b(this.d, fillInTheBlankQuestion.d) && Intrinsics.b(this.e, fillInTheBlankQuestion.e);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.c;
    }

    public final int hashCode() {
        int iE = d0.e((this.c.hashCode() + d0.f(this.a.a.hashCode() * 31, 31, this.b)) * 31, 31, this.d);
        String str = this.e;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FillInTheBlankQuestion(prompt=");
        sb.append(this.a);
        sb.append(", segments=");
        sb.append(this.b);
        sb.append(", metadata=");
        sb.append(this.c);
        sb.append(", modelVersion=");
        sb.append(this.d);
        sb.append(", algorithm=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.c;
    }

    public /* synthetic */ FillInTheBlankQuestion(int i, QuestionElement questionElement, List list, QuestionMetadata questionMetadata, String str, String str2, k kVar) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, FillInTheBlankQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = list;
        this.c = questionMetadata;
        this.d = str;
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = str2;
        }
        if ((i & 32) == 0) {
            this.f = k.l;
        } else {
            this.f = kVar;
        }
    }
}
