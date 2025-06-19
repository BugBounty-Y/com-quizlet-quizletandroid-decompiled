package kotlin.sequences;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class j {
    public static h a(Function2 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        h hVar = new h();
        hVar.d = kotlin.coroutines.intrinsics.h.a(hVar, hVar, block);
        return hVar;
    }
}
