package androidx.compose.foundation.lazy.layout;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class f0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f0(i0 i0Var, int i) {
        super(0);
        this.a = i;
        this.b = i0Var;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                i0 i0Var = this.b;
                return Float.valueOf(i0Var.o.a() - i0Var.o.c());
            case 1:
                return Float.valueOf(this.b.o.b());
            default:
                return Float.valueOf(this.b.o.d());
        }
    }
}
