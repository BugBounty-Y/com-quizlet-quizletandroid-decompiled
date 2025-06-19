package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import assistantMode.enums.l;
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
public final class FlashcardsModeSettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e;
    public final List a;
    public final List b;
    public final com.quizlet.shared.enums.d c;
    public final boolean d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsModeSettings$$serializer.INSTANCE;
        }
    }

    static {
        l lVar = l.f;
        e = new KSerializer[]{new C5048d(lVar, 0), new C5048d(lVar, 0), null, null};
    }

    public /* synthetic */ FlashcardsModeSettings(int i, List list, List list2, com.quizlet.shared.enums.d dVar, boolean z) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, FlashcardsModeSettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = dVar;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsModeSettings)) {
            return false;
        }
        FlashcardsModeSettings flashcardsModeSettings = (FlashcardsModeSettings) obj;
        return Intrinsics.b(this.a, flashcardsModeSettings.a) && Intrinsics.b(this.b, flashcardsModeSettings.b) && this.c == flashcardsModeSettings.c && this.d == flashcardsModeSettings.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + ((this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsModeSettings(frontCardSides=");
        sb.append(this.a);
        sb.append(", rearCardSides=");
        sb.append(this.b);
        sb.append(", cardOrdering=");
        sb.append(this.c);
        sb.append(", isSortingEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }

    public FlashcardsModeSettings(List frontCardSides, List rearCardSides, com.quizlet.shared.enums.d cardOrdering, boolean z) {
        Intrinsics.checkNotNullParameter(frontCardSides, "frontCardSides");
        Intrinsics.checkNotNullParameter(rearCardSides, "rearCardSides");
        Intrinsics.checkNotNullParameter(cardOrdering, "cardOrdering");
        this.a = frontCardSides;
        this.b = rearCardSides;
        this.c = cardOrdering;
        this.d = z;
    }
}
