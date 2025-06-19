package assistantMode.types;

import androidx.compose.animation.d0;
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
public final class NormalizedOptions {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f;
    public final List a;
    public final List b;
    public final List c;
    public final List d;
    public final List e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NormalizedOptions$$serializer.INSTANCE;
        }
    }

    static {
        assistantMode.enums.j jVar = assistantMode.enums.j.f;
        C5048d c5048d = new C5048d(jVar, 0);
        assistantMode.enums.l lVar = assistantMode.enums.l.f;
        f = new KSerializer[]{c5048d, new C5048d(lVar, 0), new C5048d(lVar, 0), new C5048d(lVar, 0), new C5048d(jVar, 0)};
    }

    public /* synthetic */ NormalizedOptions(int i, List list, List list2, List list3, List list4, List list5) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, NormalizedOptions$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = list3;
        this.d = list4;
        if ((i & 16) == 0) {
            this.e = list;
        } else {
            this.e = list5;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof NormalizedOptions)) {
            return false;
        }
        NormalizedOptions normalizedOptions = (NormalizedOptions) obj;
        return Intrinsics.b(this.a, normalizedOptions.a) && Intrinsics.b(this.b, normalizedOptions.b) && Intrinsics.b(this.c, normalizedOptions.c) && Intrinsics.b(this.d, normalizedOptions.d) && Intrinsics.b(this.e, normalizedOptions.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.f(d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NormalizedOptions(enabledQuestionTypes=");
        sb.append(this.a);
        sb.append(", enabledPromptSides=");
        sb.append(this.b);
        sb.append(", enabledAnswerSides=");
        sb.append(this.c);
        sb.append(", enabledWrittenAnswerSides=");
        sb.append(this.d);
        sb.append(", enabledLocationQuestionTypes=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }

    public NormalizedOptions(List enabledQuestionTypes, List enabledPromptSides, List enabledAnswerSides, List enabledWrittenAnswerSides, List enabledLocationQuestionTypes) {
        Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
        Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
        Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
        Intrinsics.checkNotNullParameter(enabledWrittenAnswerSides, "enabledWrittenAnswerSides");
        Intrinsics.checkNotNullParameter(enabledLocationQuestionTypes, "enabledLocationQuestionTypes");
        this.a = enabledQuestionTypes;
        this.b = enabledPromptSides;
        this.c = enabledAnswerSides;
        this.d = enabledWrittenAnswerSides;
        this.e = enabledLocationQuestionTypes;
    }
}
