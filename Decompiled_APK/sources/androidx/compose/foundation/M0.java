package androidx.compose.foundation;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class M0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ N0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ M0(N0 n0, int i) {
        super(0);
        this.a = i;
        this.b = n0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Boolean.valueOf(this.b.g() > 0);
            default:
                N0 n0 = this.b;
                return Boolean.valueOf(n0.g() < n0.f());
        }
    }
}
