package kotlin.coroutines.jvm.internal;

import kotlin.jvm.internal.InterfaceC4954m;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.L;

/* loaded from: classes3.dex */
public abstract class h extends g implements InterfaceC4954m {
    private final int j;

    public h(int i, kotlin.coroutines.h hVar) {
        super(hVar);
        this.j = i;
    }

    @Override // kotlin.jvm.internal.InterfaceC4954m
    public final int getArity() {
        return this.j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final String toString() {
        if (getCompletion() != null) {
            return super.toString();
        }
        K.a.getClass();
        String strA = L.a(this);
        Intrinsics.checkNotNullExpressionValue(strA, "renderLambdaToString(...)");
        return strA;
    }
}
