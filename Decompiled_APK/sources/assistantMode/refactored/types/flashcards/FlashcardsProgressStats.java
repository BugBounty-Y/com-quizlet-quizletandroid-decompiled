package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsProgressStats {

    @NotNull
    public static final Companion Companion = new Companion();
    public final int a;
    public final int b;
    public final int c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsProgressStats$$serializer.INSTANCE;
        }
    }

    public FlashcardsProgressStats(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
    }

    public final boolean a() {
        return this.a + this.b == this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsProgressStats)) {
            return false;
        }
        FlashcardsProgressStats flashcardsProgressStats = (FlashcardsProgressStats) obj;
        return this.a == flashcardsProgressStats.a && this.b == flashcardsProgressStats.b && this.c == flashcardsProgressStats.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsProgressStats(completed=");
        sb.append(this.a);
        sb.append(", stillLearning=");
        sb.append(this.b);
        sb.append(", total=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }

    public /* synthetic */ FlashcardsProgressStats(int i, int i2, int i3, int i4) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FlashcardsProgressStats$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = i2;
        this.b = i3;
        this.c = i4;
    }
}
