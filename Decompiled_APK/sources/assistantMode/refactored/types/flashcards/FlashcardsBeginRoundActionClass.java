package assistantMode.refactored.types.flashcards;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsBeginRoundActionClass implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new kotlinx.serialization.a(K.a(Object.class), (KSerializer) null, new KSerializer[0])};
    public final Object a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsBeginRoundActionClass$$serializer.INSTANCE;
        }
    }

    public FlashcardsBeginRoundActionClass() {
        this.a = null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FlashcardsBeginRoundActionClass) && Intrinsics.b(this.a, ((FlashcardsBeginRoundActionClass) obj).a);
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("FlashcardsBeginRoundActionClass(nothing="), this.a, ")");
    }

    public /* synthetic */ FlashcardsBeginRoundActionClass(int i, Object obj) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = obj;
        }
    }
}
