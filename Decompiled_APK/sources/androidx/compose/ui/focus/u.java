package androidx.compose.ui.focus;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class u extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ t b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ u(t tVar, int i) {
        super(0);
        this.a = i;
        this.b = tVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.M0();
                break;
            default:
                t tVar = this.b;
                if (tVar.a.m) {
                    a.E(tVar);
                }
                break;
        }
        return Unit.a;
    }
}
