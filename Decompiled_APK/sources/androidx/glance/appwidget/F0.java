package androidx.glance.appwidget;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class F0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ F0(int i, long j) {
        super(0);
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new androidx.compose.ui.unit.g(this.b);
            default:
                return Long.valueOf(this.b);
        }
    }
}
