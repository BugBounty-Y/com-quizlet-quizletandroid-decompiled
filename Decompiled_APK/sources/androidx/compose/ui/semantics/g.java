package androidx.compose.ui.semantics;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public static final g c = new g(DefinitionKt.NO_Float_VALUE, new kotlin.ranges.f(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE));
    public final float a;
    public final kotlin.ranges.f b;

    public g(float f, kotlin.ranges.f fVar) {
        this.a = f;
        this.b = fVar;
        if (Float.isNaN(f)) {
            throw new IllegalArgumentException("current must not be NaN");
        }
    }

    public final kotlin.ranges.f a() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        return (this.b.hashCode() + (Float.hashCode(this.a) * 31)) * 31;
    }

    public final String toString() {
        return "ProgressBarRangeInfo(current=" + this.a + ", range=" + this.b + ", steps=0)";
    }
}
