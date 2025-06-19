package androidx.compose.foundation.layout;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D0 {
    public float a = DefinitionKt.NO_Float_VALUE;
    public boolean b = true;
    public AbstractC0382e c = null;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D0)) {
            return false;
        }
        D0 d0 = (D0) obj;
        return Float.compare(this.a, d0.a) == 0 && this.b == d0.b && Intrinsics.b(this.c, d0.c);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(Float.hashCode(this.a) * 31, 31, this.b);
        AbstractC0382e abstractC0382e = this.c;
        return (iG + (abstractC0382e == null ? 0 : abstractC0382e.hashCode())) * 31;
    }

    public final String toString() {
        return "RowColumnParentData(weight=" + this.a + ", fill=" + this.b + ", crossAxisAlignment=" + this.c + ", flowLayoutData=null)";
    }
}
