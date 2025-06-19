package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.o0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0512o0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ u0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0512o0(u0 u0Var, int i) {
        super(1);
        this.a = i;
        this.b = u0Var;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.a(((androidx.compose.ui.geometry.b) obj).a);
                break;
            default:
                androidx.compose.ui.input.pointer.n nVar = (androidx.compose.ui.input.pointer.n) obj;
                this.b.d(androidx.compose.ui.input.pointer.l.g(nVar, false));
                nVar.a();
                break;
        }
        return Unit.a;
    }
}
