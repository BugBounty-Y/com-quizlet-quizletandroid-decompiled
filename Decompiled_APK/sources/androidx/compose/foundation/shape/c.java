package androidx.compose.foundation.shape;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class c implements a {
    public final float a;

    public c(float f) {
        this.a = f;
        if (f < DefinitionKt.NO_Float_VALUE || f > 100.0f) {
            throw new IllegalArgumentException("The percent should be in the range of [0, 100]");
        }
    }

    @Override // androidx.compose.foundation.shape.a
    public final float a(long j, androidx.compose.ui.unit.b bVar) {
        return (this.a / 100.0f) * androidx.compose.ui.geometry.e.c(j);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Float.compare(this.a, ((c) obj).a) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return "CornerSize(size = " + this.a + "%)";
    }
}
