package androidx.compose.ui.window;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class b extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(s sVar, int i) {
        super(1);
        this.a = i;
        this.b = sVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                s sVar = this.b;
                sVar.show();
                return new androidx.activity.compose.c(sVar, 10);
            default:
                s sVar2 = this.b;
                if (sVar2.e.a) {
                    sVar2.d.invoke();
                }
                return Unit.a;
        }
    }
}
