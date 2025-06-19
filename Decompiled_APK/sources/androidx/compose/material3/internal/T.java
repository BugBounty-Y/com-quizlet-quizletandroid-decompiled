package androidx.compose.material3.internal;

import androidx.compose.animation.core.z0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ z0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ T(z0 z0Var, int i) {
        super(0);
        this.a = i;
        this.b = z0Var;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Boolean.valueOf(((Number) this.b.getValue()).floatValue() > DefinitionKt.NO_Float_VALUE);
            default:
                return Boolean.valueOf(((Number) this.b.getValue()).floatValue() > DefinitionKt.NO_Float_VALUE);
        }
    }
}
