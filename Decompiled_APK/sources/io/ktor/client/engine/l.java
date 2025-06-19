package io.ktor.client.engine;

import io.ktor.http.n;
import java.util.List;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class l {
    public static final Set a;

    static {
        List list = n.a;
        String[] elements = {"Date", "Expires", "Last-Modified", "If-Modified-Since", "If-Unmodified-Since"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
    }
}
