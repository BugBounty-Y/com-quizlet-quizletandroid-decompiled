package kotlin.text;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class l extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m mVar) {
        super(1);
        this.a = mVar;
    }

    public final MatchGroup a(int i) {
        return this.a.b(i);
    }

    @Override // kotlin.jvm.functions.Function1
    public final /* bridge */ /* synthetic */ Object invoke(Object obj) {
        return a(((Number) obj).intValue());
    }
}
