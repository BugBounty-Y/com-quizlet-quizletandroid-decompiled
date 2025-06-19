package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.types.F;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionElement$$serializer;
import assistantMode.types.QuestionMetadata;
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
public final class MultipleChoiceSelectAllThatApplyQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, new C5048d(QuestionElement$$serializer.INSTANCE, 0), null, null, null};
    public final QuestionElement a;
    public final List b;
    public final Integer c;
    public final QuestionMetadata d;
    public final k e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MultipleChoiceSelectAllThatApplyQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ MultipleChoiceSelectAllThatApplyQuestion(int i, QuestionElement questionElement, List list, Integer num, QuestionMetadata questionMetadata, k kVar) {
        if (11 != (i & 11)) {
            AbstractC5047c0.k(i, 11, MultipleChoiceSelectAllThatApplyQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = questionElement;
        this.b = list;
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = num;
        }
        this.d = questionMetadata;
        if ((i & 16) == 0) {
            this.e = k.m;
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
        if (!(obj instanceof MultipleChoiceSelectAllThatApplyQuestion)) {
            return false;
        }
        MultipleChoiceSelectAllThatApplyQuestion multipleChoiceSelectAllThatApplyQuestion = (MultipleChoiceSelectAllThatApplyQuestion) obj;
        return Intrinsics.b(this.a, multipleChoiceSelectAllThatApplyQuestion.a) && Intrinsics.b(this.b, multipleChoiceSelectAllThatApplyQuestion.b) && Intrinsics.b(this.c, multipleChoiceSelectAllThatApplyQuestion.c) && Intrinsics.b(this.d, multipleChoiceSelectAllThatApplyQuestion.d);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.d;
    }

    public final int hashCode() {
        int iF = d0.f(this.a.a.hashCode() * 31, 31, this.b);
        Integer num = this.c;
        return this.d.hashCode() + ((iF + (num == null ? 0 : num.hashCode())) * 31);
    }

    public final String toString() {
        return "MultipleChoiceSelectAllThatApplyQuestion(prompt=" + this.a + ", options=" + this.b + ", numCorrectOptions=" + this.c + ", metadata=" + this.d + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.d;
    }

    public MultipleChoiceSelectAllThatApplyQuestion(QuestionElement prompt, List options, Integer num, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompt;
        this.b = options;
        this.c = num;
        this.d = metadata;
        this.e = k.m;
    }
}
