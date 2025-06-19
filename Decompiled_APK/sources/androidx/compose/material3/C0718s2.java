package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.s2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0718s2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F3 b;
    public final /* synthetic */ Function0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0718s2(F3 f3, Function0 function0, int i) {
        super(1);
        this.a = i;
        this.b = f3;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                if (!this.b.c()) {
                    this.c.invoke();
                }
                break;
            default:
                if (!this.b.c()) {
                    this.c.invoke();
                }
                break;
        }
        return Unit.a;
    }
}
