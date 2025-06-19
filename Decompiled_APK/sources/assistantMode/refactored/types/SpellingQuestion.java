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
public final class SpellingQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public final QuestionElement a;
    public final String b;
    public final QuestionMetadata c;
    public final k d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return SpellingQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ SpellingQuestion(int i, QuestionElement questionElement, String str, QuestionMetadata questionMetadata, k kVar) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, SpellingQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = str;
        this.c = questionMetadata;
        if ((i & 8) == 0) {
            this.d = k.i;
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
        if (!(obj instanceof SpellingQuestion)) {
            return false;
        }
        SpellingQuestion spellingQuestion = (SpellingQuestion) obj;
        return Intrinsics.b(this.a, spellingQuestion.a) && Intrinsics.b(this.b, spellingQuestion.b) && Intrinsics.b(this.c, spellingQuestion.c);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "SpellingQuestion(prompt=" + this.a + ", answerLanguageCode=" + this.b + ", metadata=" + this.c + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.c;
    }

    public SpellingQuestion(QuestionElement prompt, String answerLanguageCode, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompt;
        this.b = answerLanguageCode;
        this.c = metadata;
        this.d = k.i;
    }
}
