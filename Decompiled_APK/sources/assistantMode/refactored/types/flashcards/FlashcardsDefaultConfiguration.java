package assistantMode.refactored.types.flashcards;

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
public final class FlashcardsDefaultConfiguration {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c;
    public final List a;
    public final List b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsDefaultConfiguration$$serializer.INSTANCE;
        }
    }

    static {
        l lVar = l.f;
        c = new KSerializer[]{new C5048d(lVar, 0), new C5048d(lVar, 0)};
    }

    public /* synthetic */ FlashcardsDefaultConfiguration(int i, List list, List list2) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, FlashcardsDefaultConfiguration$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsDefaultConfiguration)) {
            return false;
        }
        FlashcardsDefaultConfiguration flashcardsDefaultConfiguration = (FlashcardsDefaultConfiguration) obj;
        return Intrinsics.b(this.a, flashcardsDefaultConfiguration.a) && Intrinsics.b(this.b, flashcardsDefaultConfiguration.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FlashcardsDefaultConfiguration(frontCardSides=" + this.a + ", rearCardSides=" + this.b + ")";
    }
}
