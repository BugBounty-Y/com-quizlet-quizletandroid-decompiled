package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.text.p0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0514p0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ u0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0514p0(u0 u0Var, int i) {
        super(0);
        this.a = i;
        this.b = u0Var;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.onStop();
                break;
            default:
                this.b.onCancel();
                break;
        }
        return Unit.a;
    }
}
