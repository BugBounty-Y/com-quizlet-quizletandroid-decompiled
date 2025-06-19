package assistantMode.refactored.modelTypes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class DiagramShapeValue implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return DiagramShapeValue$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ DiagramShapeValue(int i, String str) {
        if (1 == (i & 1)) {
            this.a = str;
        } else {
            AbstractC5047c0.k(i, 1, DiagramShapeValue$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DiagramShapeValue) && Intrinsics.b(this.a, ((DiagramShapeValue) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("DiagramShapeValue(shape="), this.a, ")");
    }

    public DiagramShapeValue(String shape) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.a = shape;
    }
}
