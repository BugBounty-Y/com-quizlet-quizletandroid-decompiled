package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.k;
import assistantMode.types.F;
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
public final class SeparatedOptionMatchingQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e;
    public final List a;
    public final List b;
    public final QuestionMetadata c;
    public final k d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return SeparatedOptionMatchingQuestion$$serializer.INSTANCE;
        }
    }

    static {
        QuestionElement$$serializer questionElement$$serializer = QuestionElement$$serializer.INSTANCE;
        e = new KSerializer[]{new C5048d(questionElement$$serializer, 0), new C5048d(questionElement$$serializer, 0), null, null};
    }

    public /* synthetic */ SeparatedOptionMatchingQuestion(int i, List list, List list2, QuestionMetadata questionMetadata, k kVar) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, SeparatedOptionMatchingQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = questionMetadata;
        if ((i & 8) == 0) {
            this.d = k.c;
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
        if (!(obj instanceof SeparatedOptionMatchingQuestion)) {
            return false;
        }
        SeparatedOptionMatchingQuestion separatedOptionMatchingQuestion = (SeparatedOptionMatchingQuestion) obj;
        return Intrinsics.b(this.a, separatedOptionMatchingQuestion.a) && Intrinsics.b(this.b, separatedOptionMatchingQuestion.b) && Intrinsics.b(this.c, separatedOptionMatchingQuestion.c);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "SeparatedOptionMatchingQuestion(prompts=" + this.a + ", options=" + this.b + ", metadata=" + this.c + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.c;
    }

    public SeparatedOptionMatchingQuestion(ArrayList prompts, ArrayList options, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(prompts, "prompts");
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = prompts;
        this.b = options;
        this.c = metadata;
        this.d = k.c;
    }
}
