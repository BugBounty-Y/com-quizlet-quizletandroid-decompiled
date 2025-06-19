package io.ktor.http;

import androidx.compose.animation.d0;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p {
    public static final p b;
    public static final p c;
    public static final p d;
    public final String a;

    static {
        p pVar = new p("GET");
        b = pVar;
        p pVar2 = new p("POST");
        c = pVar2;
        p pVar3 = new p("PUT");
        p pVar4 = new p("PATCH");
        p pVar5 = new p("DELETE");
        p pVar6 = new p("HEAD");
        d = pVar6;
        B.j(pVar, pVar2, pVar3, pVar4, pVar5, pVar6, new p("OPTIONS"));
    }

    public p(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && Intrinsics.b(this.a, ((p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return d0.r(new StringBuilder("HttpMethod(value="), this.a, ')');
    }
}
