package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.types.QuestionElement$$serializer;
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
public final class FITBMCQBlankSegment implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {null, null, new C5048d(QuestionElement$$serializer.INSTANCE, 0)};
    public final String a;
    public final long b;
    public final List c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FITBMCQBlankSegment$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FITBMCQBlankSegment(int i, String str, long j, List list) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FITBMCQBlankSegment$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = j;
        this.c = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FITBMCQBlankSegment)) {
            return false;
        }
        FITBMCQBlankSegment fITBMCQBlankSegment = (FITBMCQBlankSegment) obj;
        return Intrinsics.b(this.a, fITBMCQBlankSegment.a) && this.b == fITBMCQBlankSegment.b && Intrinsics.b(this.c, fITBMCQBlankSegment.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FITBMCQBlankSegment(answerLanguageCode=");
        sb.append(this.a);
        sb.append(", blankId=");
        sb.append(this.b);
        sb.append(", options=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }

    public FITBMCQBlankSegment(String answerLanguageCode, long j, List options) {
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        Intrinsics.checkNotNullParameter(options, "options");
        this.a = answerLanguageCode;
        this.b = j;
        this.c = options;
    }
}
