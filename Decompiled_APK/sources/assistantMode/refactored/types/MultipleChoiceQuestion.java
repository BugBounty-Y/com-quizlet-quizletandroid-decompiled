package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.types.F;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
import assistantMode.types.QuestionMetadata;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class MultipleChoiceQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] g = {null, null, new C5048d(QuestionElement$$serializer.INSTANCE, 0), null, null, null};
    public final QuestionElement a;
    public final QuestionElement b;
    public final List c;
    public final boolean d;
    public final QuestionMetadata e;
    public final k f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MultipleChoiceQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ MultipleChoiceQuestion(int i, QuestionElement questionElement, QuestionElement questionElement2, List list, boolean z, QuestionMetadata questionMetadata, k kVar) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, MultipleChoiceQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = questionElement2;
        this.c = list;
        this.d = z;
        this.e = questionMetadata;
        if ((i & 32) == 0) {
            this.f = k.d;
        } else {
            this.f = kVar;
        }
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MultipleChoiceQuestion)) {
            return false;
        }
        MultipleChoiceQuestion multipleChoiceQuestion = (MultipleChoiceQuestion) obj;
        return Intrinsics.b(this.a, multipleChoiceQuestion.a) && Intrinsics.b(this.b, multipleChoiceQuestion.b) && Intrinsics.b(this.c, multipleChoiceQuestion.c) && this.d == multipleChoiceQuestion.d && Intrinsics.b(this.e, multipleChoiceQuestion.e);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.e;
    }

    public final int hashCode() {
        int iHashCode = this.a.a.hashCode() * 31;
        QuestionElement questionElement = this.b;
        return this.e.hashCode() + d0.g(d0.f((iHashCode + (questionElement == null ? 0 : questionElement.a.hashCode())) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "MultipleChoiceQuestion(prompt=" + this.a + ", hint=" + this.b + ", options=" + this.c + ", hasExactlyOneCorrectAnswer=" + this.d + ", metadata=" + this.e + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.e;
    }

    public MultipleChoiceQuestion(QuestionElement prompt, QuestionElement questionElement, ArrayList options, boolean z, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompt;
        this.b = questionElement;
        this.c = options;
        this.d = z;
        this.e = metadata;
        this.f = k.d;
    }
}
