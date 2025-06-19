package kotlin.coroutines.jvm.internal;

import kotlin.jvm.internal.InterfaceC4954m;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.L;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class i extends c implements InterfaceC4954m {
    private final int arity;

    public i(int i, kotlin.coroutines.h hVar) {
        super(hVar);
        this.arity = i;
    }

    @Override // kotlin.jvm.internal.InterfaceC4954m
    public int getArity() {
        return this.arity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    @NotNull
    public String toString() {
        if (getCompletion() != null) {
            return super.toString();
        }
        K.a.getClass();
        String strA = L.a(this);
        Intrinsics.checkNotNullExpressionValue(strA, "renderLambdaToString(...)");
        return strA;
    }
}
