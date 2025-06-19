package io.ktor.http;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q {
    public static final q d = new q("HTTP", 2, 0);
    public static final q e = new q("HTTP", 1, 1);
    public static final q f = new q("HTTP", 1, 0);
    public static final q g = new q("SPDY", 3, 0);
    public static final q h = new q("QUIC", 1, 0);
    public final String a;
    public final int b;
    public final int c;

    public q(String name, int i, int i2) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
        this.b = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a.equals(qVar.a) && this.b == qVar.b && this.c == qVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return this.a + '/' + this.b + '.' + this.c;
    }
}
