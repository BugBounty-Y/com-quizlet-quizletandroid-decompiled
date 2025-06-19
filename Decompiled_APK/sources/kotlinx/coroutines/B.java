package kotlinx.coroutines;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.a {
    public static final C5023i0 b = new C5023i0();
    public final String a;

    public B(String str) {
        super(b);
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof B) && Intrinsics.b(this.a, ((B) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return androidx.compose.animation.d0.r(new StringBuilder("CoroutineName("), this.a, ')');
    }
}
