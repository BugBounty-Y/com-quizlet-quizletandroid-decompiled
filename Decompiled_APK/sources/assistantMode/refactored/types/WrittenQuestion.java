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
public final class WrittenQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public final QuestionElement a;
    public final String b;
    public final QuestionElement c;
    public final QuestionMetadata d;
    public final k e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return WrittenQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ WrittenQuestion(int i, QuestionElement questionElement, String str, QuestionElement questionElement2, QuestionMetadata questionMetadata, k kVar) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, WrittenQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = str;
        this.c = questionElement2;
        this.d = questionMetadata;
        if ((i & 16) == 0) {
            this.e = k.b;
        } else {
            this.e = kVar;
        }
    }

    public static WrittenQuestion b(WrittenQuestion writtenQuestion) {
        QuestionElement prompt = writtenQuestion.a;
        String answerLanguageCode = writtenQuestion.b;
        QuestionMetadata metadata = writtenQuestion.d;
        writtenQuestion.getClass();
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        return new WrittenQuestion(prompt, answerLanguageCode, null, metadata);
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WrittenQuestion)) {
            return false;
        }
        WrittenQuestion writtenQuestion = (WrittenQuestion) obj;
        return Intrinsics.b(this.a, writtenQuestion.a) && Intrinsics.b(this.b, writtenQuestion.b) && Intrinsics.b(this.c, writtenQuestion.c) && Intrinsics.b(this.d, writtenQuestion.d);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.d;
    }

    public final int hashCode() {
        int iE = d0.e(this.a.a.hashCode() * 31, 31, this.b);
        QuestionElement questionElement = this.c;
        return this.d.hashCode() + ((iE + (questionElement == null ? 0 : questionElement.a.hashCode())) * 31);
    }

    public final String toString() {
        return "WrittenQuestion(prompt=" + this.a + ", answerLanguageCode=" + this.b + ", hint=" + this.c + ", metadata=" + this.d + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.d;
    }

    public WrittenQuestion(QuestionElement prompt, String answerLanguageCode, QuestionElement questionElement, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompt;
        this.b = answerLanguageCode;
        this.c = questionElement;
        this.d = metadata;
        this.e = k.b;
    }
}
