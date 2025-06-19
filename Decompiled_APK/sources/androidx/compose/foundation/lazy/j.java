package androidx.compose.foundation.lazy;

import androidx.compose.foundation.lazy.layout.N;
import androidx.compose.runtime.InterfaceC0773a0;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class j extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ j(InterfaceC0773a0 interfaceC0773a0, int i) {
        super(0);
        this.a = i;
        this.b = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new g((Function1) this.b.getValue());
            case 1:
                return new androidx.compose.foundation.lazy.grid.i((Function1) this.b.getValue());
            case 2:
                return (N) ((Function0) this.b.getValue()).invoke();
            case 3:
                InterfaceC0773a0 interfaceC0773a0 = this.b;
                if (interfaceC0773a0 != null) {
                    return (List) interfaceC0773a0.getValue();
                }
                return null;
            case 4:
                Boolean bool = (Boolean) this.b.getValue();
                bool.booleanValue();
                return bool;
            case 5:
                return (androidx.compose.material.ripple.f) this.b.getValue();
            default:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                return Unit.a;
        }
    }
}
