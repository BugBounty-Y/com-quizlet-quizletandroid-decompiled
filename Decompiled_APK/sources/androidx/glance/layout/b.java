package androidx.glance.layout;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class b {
    public final int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static final /* synthetic */ b a(int i) {
        return new b(i);
    }

    public static String b(int i) {
        return d0.m(')', i, "Vertical(value=");
    }

    public final boolean equals(Object obj) {
        if (obj instanceof b) {
            return this.a == ((b) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return b(this.a);
    }
}
