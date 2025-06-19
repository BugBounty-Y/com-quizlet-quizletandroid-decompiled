package kotlin.text;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w extends kotlin.jvm.internal.r implements Function1 {
    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final String invoke(String it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return StringsKt.O(it2) ? it2.length() < 2 ? "  " : it2 : "  ".concat(it2);
    }
}
