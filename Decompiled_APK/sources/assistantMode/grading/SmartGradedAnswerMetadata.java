package assistantMode.grading;

import androidx.compose.animation.d0;
import com.quizlet.shared.models.api.grading.LongtextGradingResult;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class SmartGradedAnswerMetadata implements b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final LongtextGradingResult a;
    public final boolean b;
    public final long c;
    public final long d;
    public final Long e;
    public final boolean f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return SmartGradedAnswerMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ SmartGradedAnswerMetadata(int i, LongtextGradingResult longtextGradingResult, boolean z, long j, long j2, Long l, boolean z2) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, SmartGradedAnswerMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = longtextGradingResult;
        this.b = z;
        this.c = j;
        this.d = j2;
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = l;
        }
        if ((i & 32) == 0) {
            this.f = true;
        } else {
            this.f = z2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SmartGradedAnswerMetadata)) {
            return false;
        }
        SmartGradedAnswerMetadata smartGradedAnswerMetadata = (SmartGradedAnswerMetadata) obj;
        return Intrinsics.b(this.a, smartGradedAnswerMetadata.a) && this.b == smartGradedAnswerMetadata.b && this.c == smartGradedAnswerMetadata.c && this.d == smartGradedAnswerMetadata.d && Intrinsics.b(this.e, smartGradedAnswerMetadata.e) && this.f == smartGradedAnswerMetadata.f;
    }

    public final int hashCode() {
        LongtextGradingResult longtextGradingResult = this.a;
        int iD = d0.d(d0.d(d0.g((longtextGradingResult == null ? 0 : longtextGradingResult.hashCode()) * 31, 31, this.b), 31, this.c), 31, this.d);
        Long l = this.e;
        return Boolean.hashCode(this.f) + ((iD + (l != null ? l.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SmartGradedAnswerMetadata(longtextGradingResult=");
        sb.append(this.a);
        sb.append(", wasRequestSuccess=");
        sb.append(this.b);
        sb.append(", logStartTimestamp=");
        sb.append(this.c);
        sb.append(", logEndTimestamp=");
        sb.append(this.d);
        sb.append(", logGradedResultTimestamp=");
        sb.append(this.e);
        sb.append(", wasSmartGradingUsed=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }

    public SmartGradedAnswerMetadata(LongtextGradingResult longtextGradingResult, boolean z, long j, long j2, Long l, int i) {
        l = (i & 16) != 0 ? null : l;
        this.a = longtextGradingResult;
        this.b = z;
        this.c = j;
        this.d = j2;
        this.e = l;
        this.f = true;
    }
}
