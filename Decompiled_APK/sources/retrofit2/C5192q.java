package retrofit2;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: retrofit2.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5192q implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC5179d b;

    public /* synthetic */ C5192q(InterfaceC5179d interfaceC5179d, int i) {
        this.a = i;
        this.b = interfaceC5179d;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.cancel();
                break;
            case 1:
                this.b.cancel();
                break;
            default:
                this.b.cancel();
                break;
        }
        return Unit.a;
    }
}
