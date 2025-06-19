package androidx.glance.layout;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n {
    public final float a;
    public final List b;

    static {
        new n(DefinitionKt.NO_Float_VALUE, 3);
    }

    public n(float f, int i) {
        this((i & 1) != 0 ? 0 : f, K.a);
    }

    public final n a(n nVar) {
        return new n(this.a + nVar.a, CollectionsKt.c0(this.b, nVar.b));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return androidx.compose.ui.unit.e.a(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PaddingDimension(dp=" + ((Object) androidx.compose.ui.unit.e.b(this.a)) + ", resourceIds=" + this.b + ')';
    }

    public n(float f, List list) {
        this.a = f;
        this.b = list;
    }
}
