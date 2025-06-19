package androidx.compose.foundation.lazy;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class C extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(int i, int i2) {
        super(0);
        this.a = i2;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new A(this.b, 0);
            case 1:
                return new androidx.compose.foundation.lazy.grid.A(this.b, 0);
            default:
                int i = this.b;
                if (i == 1) {
                    return "b";
                }
                if (i == 2) {
                    return "i";
                }
                throw new IllegalArgumentException();
        }
    }
}
