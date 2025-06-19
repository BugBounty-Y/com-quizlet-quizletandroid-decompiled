package androidx.compose.foundation;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.ui.graphics.C0861v;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A0 {
    public final long a;
    public final androidx.compose.foundation.layout.A0 b;

    public A0() {
        long jD = androidx.compose.ui.graphics.F.d(4284900966L);
        androidx.compose.foundation.layout.A0 a0C = AbstractC0382e.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 3);
        this.a = jD;
        this.b = a0C;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!A0.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.foundation.OverscrollConfiguration");
        A0 a0 = (A0) obj;
        return C0861v.c(this.a, a0.a) && Intrinsics.b(this.b, a0.b);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OverscrollConfiguration(glowColor=");
        androidx.compose.animation.d0.x(this.a, ", drawPadding=", sb);
        sb.append(this.b);
        sb.append(')');
        return sb.toString();
    }
}
