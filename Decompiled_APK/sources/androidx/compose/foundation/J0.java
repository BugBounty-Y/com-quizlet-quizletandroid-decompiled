package androidx.compose.foundation;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class J0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ K0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ J0(K0 k0, int i) {
        super(0);
        this.a = i;
        this.b = k0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Float.valueOf(this.b.n.g());
            default:
                return Float.valueOf(this.b.n.f());
        }
    }
}
