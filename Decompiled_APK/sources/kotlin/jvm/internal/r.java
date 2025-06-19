package kotlin.jvm.internal;

import java.io.Serializable;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class r implements InterfaceC4954m, Serializable {
    private final int arity;

    public r(int i) {
        this.arity = i;
    }

    @Override // kotlin.jvm.internal.InterfaceC4954m
    public int getArity() {
        return this.arity;
    }

    @NotNull
    public String toString() {
        K.a.getClass();
        String strA = L.a(this);
        Intrinsics.checkNotNullExpressionValue(strA, "renderLambdaToString(...)");
        return strA;
    }
}
