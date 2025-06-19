package assistantMode.types;

import java.lang.annotation.Annotation;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class Feedback {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {new kotlinx.serialization.c(K.a(v.class), new Annotation[0]), new kotlinx.serialization.c(K.a(v.class), new Annotation[0]), null, new kotlinx.serialization.internal.F(kotlinx.serialization.internal.K.a, QuestionElement$$serializer.INSTANCE, 1), null};
    public final v a;
    public final v b;
    public final QuestionElement c;
    public final Map d;
    public final Boolean e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Feedback$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Feedback(int i, v vVar, v vVar2, QuestionElement questionElement, Map map, Boolean bool) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, Feedback$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = vVar;
        this.b = vVar2;
        this.c = questionElement;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = map;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Feedback)) {
            return false;
        }
        Feedback feedback = (Feedback) obj;
        return Intrinsics.b(this.a, feedback.a) && Intrinsics.b(this.b, feedback.b) && Intrinsics.b(this.c, feedback.c) && Intrinsics.b(this.d, feedback.d) && Intrinsics.b(this.e, feedback.e);
    }

    public final int hashCode() {
        v vVar = this.a;
        int iHashCode = (this.b.hashCode() + ((vVar == null ? 0 : vVar.hashCode()) * 31)) * 31;
        QuestionElement questionElement = this.c;
        int iHashCode2 = (iHashCode + (questionElement == null ? 0 : questionElement.a.hashCode())) * 31;
        Map map = this.d;
        int iHashCode3 = (iHashCode2 + (map == null ? 0 : map.hashCode())) * 31;
        Boolean bool = this.e;
        return iHashCode3 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        return "Feedback(submittedAnswer=" + this.a + ", expectedAnswer=" + this.b + ", expectedAnswerDescription=" + this.c + ", explanations=" + this.d + ", isCompleteAnswer=" + this.e + ")";
    }

    public Feedback(v vVar, v expectedAnswer, QuestionElement questionElement, Map map, Boolean bool) {
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        this.a = vVar;
        this.b = expectedAnswer;
        this.c = questionElement;
        this.d = map;
        this.e = bool;
    }

    public /* synthetic */ Feedback(v vVar, v vVar2, QuestionElement questionElement, Boolean bool, int i) {
        this(vVar, vVar2, questionElement, (Map) null, (i & 16) != 0 ? null : bool);
    }
}
