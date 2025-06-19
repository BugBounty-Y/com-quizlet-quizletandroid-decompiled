package kotlin.text;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v extends kotlin.jvm.internal.r implements Function1 {
    public static final v a = new v(1);

    public v() {
        super(1);
    }

    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final String invoke(String line) {
        Intrinsics.checkNotNullParameter(line, "line");
        return line;
    }
}
