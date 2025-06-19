package assistantMode.types;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class QuestionScoringInferenceMetadata {

    @NotNull
    public static final Companion Companion = new Companion();
    public final double a;
    public final String b;
    public final String c;
    public final Double d;
    public final String e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return QuestionScoringInferenceMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ QuestionScoringInferenceMetadata(int i, double d, String str, String str2, Double d2, String str3) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, QuestionScoringInferenceMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = d;
        this.b = str;
        this.c = str2;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = d2;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = str3;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionScoringInferenceMetadata)) {
            return false;
        }
        QuestionScoringInferenceMetadata questionScoringInferenceMetadata = (QuestionScoringInferenceMetadata) obj;
        return Double.compare(this.a, questionScoringInferenceMetadata.a) == 0 && Intrinsics.b(this.b, questionScoringInferenceMetadata.b) && Intrinsics.b(this.c, questionScoringInferenceMetadata.c) && Intrinsics.b(this.d, questionScoringInferenceMetadata.d) && Intrinsics.b(this.e, questionScoringInferenceMetadata.e);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(Double.hashCode(this.a) * 31, 31, this.b), 31, this.c);
        Double d = this.d;
        int iHashCode = (iE + (d == null ? 0 : d.hashCode())) * 31;
        String str = this.e;
        return iHashCode + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionScoringInferenceMetadata(currentScore=");
        sb.append(this.a);
        sb.append(", modelVersion=");
        sb.append(this.b);
        sb.append(", modelName=");
        sb.append(this.c);
        sb.append(", priorityScore=");
        sb.append(this.d);
        sb.append(", priorityMethod=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
