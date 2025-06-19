package androidx.compose.ui.semantics;

import kotlin.InterfaceC4938g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final InterfaceC4938g b;

    public a(String str, InterfaceC4938g interfaceC4938g) {
        this.a = str;
        this.b = interfaceC4938g;
    }

    public final String a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str != null ? str.hashCode() : 0) * 31;
        InterfaceC4938g interfaceC4938g = this.b;
        return iHashCode + (interfaceC4938g != null ? interfaceC4938g.hashCode() : 0);
    }

    public final String toString() {
        return "AccessibilityAction(label=" + this.a + ", action=" + this.b + ')';
    }
}
