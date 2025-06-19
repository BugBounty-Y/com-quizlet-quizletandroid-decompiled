package androidx.compose.ui.node;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0906b extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0907c b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0906b(C0907c c0907c, int i) {
        super(0);
        this.a = i;
        this.b = c0907c;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.O0();
                break;
            default:
                C0907c c0907c = this.b;
                androidx.compose.ui.o oVar = c0907c.n;
                Intrinsics.e(oVar, "null cannot be cast to non-null type androidx.compose.ui.modifier.ModifierLocalConsumer");
                ((androidx.compose.ui.modifier.c) oVar).j(c0907c);
                break;
        }
        return Unit.a;
    }
}
