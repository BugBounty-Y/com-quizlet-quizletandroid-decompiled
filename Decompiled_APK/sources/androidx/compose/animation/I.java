package androidx.compose.animation;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I {
    public final androidx.compose.ui.i a;
    public final Function1 b;
    public final androidx.compose.animation.core.D c;

    public I(androidx.compose.animation.core.D d, androidx.compose.ui.i iVar, Function1 function1) {
        this.a = iVar;
        this.b = function1;
        this.c = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return this.a.equals(i.a) && this.b.equals(i.b) && Intrinsics.b(this.c, i.c);
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "ChangeSize(alignment=" + this.a + ", size=" + this.b + ", animationSpec=" + this.c + ", clip=true)";
    }
}
