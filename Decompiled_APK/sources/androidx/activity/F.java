package androidx.activity;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class F extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ L b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ F(L l, int i) {
        super(0);
        this.a = i;
        this.b = l;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.c();
                break;
            case 1:
                this.b.b();
                break;
            default:
                this.b.c();
                break;
        }
        return Unit.a;
    }
}
