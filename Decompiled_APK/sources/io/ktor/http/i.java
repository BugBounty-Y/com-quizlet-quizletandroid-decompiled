package io.ktor.http;

import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class i {
    public static final Set a;

    static {
        Character[] elements = {'(', ')', '<', '>', '@', ',', ';', ':', '\\', '\"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t', '\n', '\r'};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
    }
}
