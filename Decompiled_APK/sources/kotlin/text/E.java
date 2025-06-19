package kotlin.text;

import kotlin.Pair;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ char[] a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(char[] cArr) {
        super(2);
        this.a = cArr;
    }

    public final Pair<Integer, Integer> a(CharSequence $receiver, int i) {
        Intrinsics.checkNotNullParameter($receiver, "$this$$receiver");
        int iU = StringsKt__StringsKt.u($receiver, this.a, i, false);
        if (iU < 0) {
            return null;
        }
        return new Pair<>(Integer.valueOf(iU), 1);
    }

    @Override // kotlin.jvm.functions.Function2
    public final /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2) {
        return a((CharSequence) obj, ((Number) obj2).intValue());
    }
}
