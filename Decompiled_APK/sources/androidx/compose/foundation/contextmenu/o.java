package androidx.compose.foundation.contextmenu;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o {
    public final InterfaceC0773a0 a = C0776c.z(l.a);

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof o) {
            return Intrinsics.b((n) ((L0) ((o) obj).a).getValue(), (n) ((L0) this.a).getValue());
        }
        return false;
    }

    public final int hashCode() {
        return ((n) ((L0) this.a).getValue()).hashCode();
    }

    public final String toString() {
        return "ContextMenuState(status=" + ((n) ((L0) this.a).getValue()) + ')';
    }
}
