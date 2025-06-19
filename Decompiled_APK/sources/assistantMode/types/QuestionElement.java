package assistantMode.types;

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
public final class QuestionElement {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new C5048d(new kotlinx.serialization.c(K.a(assistantMode.types.unions.a.class), new Annotation[0]), 0)};
    public final List a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return QuestionElement$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ QuestionElement(int i, List list) {
        if (1 == (i & 1)) {
            this.a = list;
        } else {
            AbstractC5047c0.k(i, 1, QuestionElement$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof QuestionElement) && Intrinsics.b(this.a, ((QuestionElement) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("QuestionElement(attributes="), this.a);
    }

    public QuestionElement(List attributes) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = attributes;
    }
}
