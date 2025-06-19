package io.ktor.client.statement;

import io.ktor.http.o;
import io.ktor.http.q;
import io.ktor.http.r;
import io.ktor.utils.io.n;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public abstract class b implements o, C {
    public abstract io.ktor.client.call.b b();

    public abstract n c();

    public abstract io.ktor.util.date.d d();

    public abstract io.ktor.util.date.d e();

    public abstract r g();

    public abstract q h();

    public final String toString() {
        StringBuilder sb = new StringBuilder("HttpResponse[");
        Intrinsics.checkNotNullParameter(this, "<this>");
        sb.append(b().c().i());
        sb.append(", ");
        sb.append(g());
        sb.append(']');
        return sb.toString();
    }
}
