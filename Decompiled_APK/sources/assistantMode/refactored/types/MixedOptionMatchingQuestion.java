package assistantMode.refactored.types;

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
public final class MixedOptionMatchingQuestion implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {new C5048d(QuestionElement$$serializer.INSTANCE, 0), null, null};
    public final List a;
    public final QuestionMetadata b;
    public final k c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MixedOptionMatchingQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ MixedOptionMatchingQuestion(int i, List list, QuestionMetadata questionMetadata, k kVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, MixedOptionMatchingQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = questionMetadata;
        if ((i & 4) == 0) {
            this.c = k.k;
        } else {
            this.c = kVar;
        }
    }

    @Override // assistantMode.refactored.types.d
    public final k a() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MixedOptionMatchingQuestion)) {
            return false;
        }
        MixedOptionMatchingQuestion mixedOptionMatchingQuestion = (MixedOptionMatchingQuestion) obj;
        return Intrinsics.b(this.a, mixedOptionMatchingQuestion.a) && Intrinsics.b(this.b, mixedOptionMatchingQuestion.b);
    }

    @Override // assistantMode.refactored.types.d, assistantMode.refactored.types.g
    public final QuestionMetadata getMetadata() {
        return this.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MixedOptionMatchingQuestion(options=" + this.a + ", metadata=" + this.b + ")";
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.b;
    }

    public MixedOptionMatchingQuestion(ArrayList options, QuestionMetadata metadata) {
        Intrinsics.checkNotNullParameter(options, "options");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = options;
        this.b = metadata;
        this.c = k.k;
    }
}
