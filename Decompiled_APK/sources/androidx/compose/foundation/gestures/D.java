package androidx.compose.foundation.gestures;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class D extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ D(int i, Function0 function0) {
        super(1);
        this.a = i;
        this.b = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.invoke();
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                long j = ((androidx.compose.ui.geometry.b) obj).a;
                this.b.invoke();
                break;
            case 4:
                this.b.invoke();
                break;
            case 5:
                long j2 = ((androidx.compose.ui.geometry.b) obj).a;
                this.b.invoke();
                break;
            case 6:
                androidx.compose.ui.semantics.t.g((androidx.compose.ui.semantics.v) obj, new androidx.compose.ui.semantics.g(((Number) this.b.invoke()).floatValue(), new kotlin.ranges.f(DefinitionKt.NO_Float_VALUE, 1.0f)));
                break;
            default:
                androidx.compose.ui.semantics.t.g((androidx.compose.ui.semantics.v) obj, new androidx.compose.ui.semantics.g(((Number) this.b.invoke()).floatValue(), new kotlin.ranges.f(DefinitionKt.NO_Float_VALUE, 1.0f)));
                break;
        }
        return Unit.a;
    }
}
