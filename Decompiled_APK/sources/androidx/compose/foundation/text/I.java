package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class I extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ I(androidx.compose.foundation.text.selection.i0 i0Var, int i) {
        super(0);
        this.a = i;
        this.b = i0Var;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.n();
                break;
            case 1:
                this.b.h(true);
                break;
            case 2:
                this.b.d(true);
                break;
            case 3:
                this.b.f();
                break;
            case 4:
                androidx.compose.foundation.text.selection.i0 i0Var = this.b;
                i0Var.d(true);
                i0Var.m();
                break;
            case 5:
                androidx.compose.foundation.text.selection.i0 i0Var2 = this.b;
                i0Var2.f();
                i0Var2.m();
                break;
            case 6:
                androidx.compose.foundation.text.selection.i0 i0Var3 = this.b;
                i0Var3.n();
                i0Var3.m();
                break;
            default:
                this.b.o();
                break;
        }
        return Unit.a;
    }
}
