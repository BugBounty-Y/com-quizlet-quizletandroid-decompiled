package kotlinx.serialization.modules;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends IllegalArgumentException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(String msg) {
        super(msg);
        Intrinsics.checkNotNullParameter(msg, "msg");
    }
}
