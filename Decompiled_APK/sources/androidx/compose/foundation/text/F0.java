package androidx.compose.foundation.text;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class F0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ I0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ F0(I0 i0, int i) {
        super(0);
        this.a = i;
        this.b = i0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Boolean.valueOf(this.b.a() > DefinitionKt.NO_Float_VALUE);
            default:
                I0 i0 = this.b;
                return Boolean.valueOf(i0.a() < i0.b.i());
        }
    }
}
