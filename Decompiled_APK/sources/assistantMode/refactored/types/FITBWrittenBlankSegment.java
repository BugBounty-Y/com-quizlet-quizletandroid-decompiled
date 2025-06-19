package assistantMode.refactored.types;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FITBWrittenBlankSegment implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final long b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FITBWrittenBlankSegment$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FITBWrittenBlankSegment(int i, long j, String str) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, FITBWrittenBlankSegment$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FITBWrittenBlankSegment)) {
            return false;
        }
        FITBWrittenBlankSegment fITBWrittenBlankSegment = (FITBWrittenBlankSegment) obj;
        return Intrinsics.b(this.a, fITBWrittenBlankSegment.a) && this.b == fITBWrittenBlankSegment.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FITBWrittenBlankSegment(answerLanguageCode=");
        sb.append(this.a);
        sb.append(", blankId=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }

    public FITBWrittenBlankSegment(String answerLanguageCode, long j) {
        Intrinsics.checkNotNullParameter(answerLanguageCode, "answerLanguageCode");
        this.a = answerLanguageCode;
        this.b = j;
    }
}
