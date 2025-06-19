package io.ktor.client.call;

import io.ktor.http.k;
import io.ktor.http.n;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;

@Metadata
/* loaded from: classes3.dex */
public final class NoTransformationFoundException extends UnsupportedOperationException {
    public final String a;

    public NoTransformationFoundException(io.ktor.client.statement.b response, C4950i from, C4950i to) {
        Intrinsics.checkNotNullParameter(response, "response");
        Intrinsics.checkNotNullParameter(from, "from");
        Intrinsics.checkNotNullParameter(to, "to");
        StringBuilder sb = new StringBuilder("\n        Expected response body of the type '");
        sb.append(to);
        sb.append("' but was '");
        sb.append(from);
        sb.append("'\n        In response from `");
        Intrinsics.checkNotNullParameter(response, "<this>");
        sb.append(response.b().c().i());
        sb.append("`\n        Response status `");
        sb.append(response.g());
        sb.append("`\n        Response header `ContentType: ");
        k kVarA = response.a();
        List list = n.a;
        sb.append(kVarA.d("Content-Type"));
        sb.append("` \n        Request header `Accept: ");
        Intrinsics.checkNotNullParameter(response, "<this>");
        sb.append(response.b().c().a().d("Accept"));
        sb.append("`\n        \n        You can read how to resolve NoTransformationFoundException at FAQ: \n        https://ktor.io/docs/faq.html#no-transformation-found-exception\n    ");
        this.a = x.c(sb.toString());
    }

    @Override // java.lang.Throwable
    public final String getMessage() {
        return this.a;
    }
}
