package assistantMode.refactored.types;

import assistantMode.types.unions.TextAttribute;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FITBTextSegment implements b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final TextAttribute a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FITBTextSegment$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FITBTextSegment(int i, TextAttribute textAttribute) {
        if (1 == (i & 1)) {
            this.a = textAttribute;
        } else {
            AbstractC5047c0.k(i, 1, FITBTextSegment$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FITBTextSegment) && Intrinsics.b(this.a, ((FITBTextSegment) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FITBTextSegment(text=" + this.a + ")";
    }

    public FITBTextSegment(TextAttribute text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }
}
