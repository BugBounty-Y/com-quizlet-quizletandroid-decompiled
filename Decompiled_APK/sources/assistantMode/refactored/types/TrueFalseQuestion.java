package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.types.F;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class TrueFalseQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public final QuestionElement a;
    public final QuestionElement b;
    public final QuestionMetadata c;
    public final k d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TrueFalseQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TrueFalseQuestion(int i, QuestionElement questionElement, QuestionElement questionElement2, QuestionMetadata questionMetadata, k kVar) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, TrueFalseQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = questionElement2;
        this.c = questionMetadata;
        if ((i & 8) == 0) {
            this.d = k.e;
        } else {
            this.d = kVar;
        }
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TrueFalseQuestion)) {
            return false;
        }
        TrueFalseQuestion trueFalseQuestion = (TrueFalseQuestion) obj;
        return Intrinsics.b(this.a, trueFalseQuestion.a) && Intrinsics.b(this.b, trueFalseQuestion.b) && Intrinsics.b(this.c, trueFalseQuestion.c);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.a.hashCode() * 31, 31, this.b.a);
    }

    public final String toString() {
        return "TrueFalseQuestion(prompt=" + this.a + ", goesWith=" + this.b + ", metadata=" + this.c + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.c;
    }

    public TrueFalseQuestion(QuestionElement prompt, QuestionElement goesWith, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(goesWith, "goesWith");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompt;
        this.b = goesWith;
        this.c = metadata;
        this.d = k.e;
    }
}
