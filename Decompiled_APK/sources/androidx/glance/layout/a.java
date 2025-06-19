package androidx.glance.layout;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class a {
    public final int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static final /* synthetic */ a a(int i) {
        return new a(i);
    }

    public static String b(int i) {
        return d0.m(')', i, "Horizontal(value=");
    }

    public final boolean equals(Object obj) {
        if (obj instanceof a) {
            return this.a == ((a) obj).a;
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
