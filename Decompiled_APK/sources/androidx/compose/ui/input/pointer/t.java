package androidx.compose.ui.input.pointer;

/* loaded from: classes.dex */
public final class t {
    public final int a;

    public /* synthetic */ t(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof t) {
            return this.a == ((t) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("PointerKeyboardModifiers(packedValue="), this.a, ')');
    }
}
