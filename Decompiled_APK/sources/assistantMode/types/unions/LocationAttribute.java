package assistantMode.types.unions;

import assistantMode.refactored.enums.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class LocationAttribute implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final ImageAttribute b;
    public final h c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return LocationAttribute$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ LocationAttribute(int i, String str, ImageAttribute imageAttribute, h hVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, LocationAttribute$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = imageAttribute;
        if ((i & 4) == 0) {
            this.c = h.f;
        } else {
            this.c = hVar;
        }
    }

    @Override // assistantMode.types.unions.a
    public final h a() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LocationAttribute)) {
            return false;
        }
        LocationAttribute locationAttribute = (LocationAttribute) obj;
        return Intrinsics.b(this.a, locationAttribute.a) && Intrinsics.b(this.b, locationAttribute.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        ImageAttribute imageAttribute = this.b;
        return iHashCode + (imageAttribute == null ? 0 : imageAttribute.hashCode());
    }

    public final String toString() {
        return "LocationAttribute(shape=" + this.a + ", diagramImage=" + this.b + ")";
    }

    public LocationAttribute(String shape, ImageAttribute imageAttribute) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.a = shape;
        this.b = imageAttribute;
        this.c = h.f;
    }
}
