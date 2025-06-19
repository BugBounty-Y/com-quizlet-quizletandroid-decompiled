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
public final class QuestionStudiableMetadata {

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
            return QuestionStudiableMetadata$$serializer.INSTANCE;
        }
    }

    static {
        assistantMode.enums.r rVar = assistantMode.enums.r.f;
        f = new KSerializer[]{new C5048d(rVar, 0), new C5048d(rVar, 0), new C5048d(rVar, 0), new C5048d(rVar, 0), new C5048d(rVar, 0)};
    }

    public /* synthetic */ QuestionStudiableMetadata(int i, List list, List list2, List list3, List list4, List list5) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, QuestionStudiableMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = list3;
        this.d = list4;
        this.e = list5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionStudiableMetadata)) {
            return false;
        }
        QuestionStudiableMetadata questionStudiableMetadata = (QuestionStudiableMetadata) obj;
        return Intrinsics.b(this.a, questionStudiableMetadata.a) && Intrinsics.b(this.b, questionStudiableMetadata.b) && Intrinsics.b(this.c, questionStudiableMetadata.c) && Intrinsics.b(this.d, questionStudiableMetadata.d) && Intrinsics.b(this.e, questionStudiableMetadata.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.f(d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuestionStudiableMetadata(unavailableForContainer=");
        sb.append(this.a);
        sb.append(", notReadyForContainer=");
        sb.append(this.b);
        sb.append(", readyForContainer=");
        sb.append(this.c);
        sb.append(", presentForItem=");
        sb.append(this.d);
        sb.append(", staleForItem=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }

    public QuestionStudiableMetadata(List unavailableForContainer, List notReadyForContainer, List readyForContainer, List presentForItem, List staleForItem) {
        Intrinsics.checkNotNullParameter(unavailableForContainer, "unavailableForContainer");
        Intrinsics.checkNotNullParameter(notReadyForContainer, "notReadyForContainer");
        Intrinsics.checkNotNullParameter(readyForContainer, "readyForContainer");
        Intrinsics.checkNotNullParameter(presentForItem, "presentForItem");
        Intrinsics.checkNotNullParameter(staleForItem, "staleForItem");
        this.a = unavailableForContainer;
        this.b = notReadyForContainer;
        this.c = readyForContainer;
        this.d = presentForItem;
        this.e = staleForItem;
    }
}
