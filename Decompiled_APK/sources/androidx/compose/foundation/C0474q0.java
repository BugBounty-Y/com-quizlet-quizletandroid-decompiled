package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0474q0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ s0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0474q0(s0 s0Var, int i) {
        super(0);
        this.a = i;
        this.b = s0Var;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.r rVar = (androidx.compose.ui.layout.r) ((androidx.compose.runtime.L0) this.b.t).getValue();
                return new androidx.compose.ui.geometry.b(rVar != null ? rVar.U(0L) : 9205357640488583168L);
            case 1:
                return new androidx.compose.ui.geometry.b(this.b.v);
            default:
                this.b.O0();
                return Unit.a;
        }
    }
}
