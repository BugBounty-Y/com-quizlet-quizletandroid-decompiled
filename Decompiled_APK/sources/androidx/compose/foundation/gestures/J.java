package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class J extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Q b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ J(Q q, int i) {
        super(0);
        this.a = i;
        this.b = q;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                kotlinx.coroutines.channels.h hVar = this.b.t;
                if (hVar != null) {
                    hVar.o(C0352u.a);
                }
                return Unit.a;
            default:
                return Boolean.valueOf(!this.b.W0());
        }
    }
}
