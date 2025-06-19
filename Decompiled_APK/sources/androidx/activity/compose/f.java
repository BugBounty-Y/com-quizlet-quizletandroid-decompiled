package androidx.activity.compose;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class f extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(boolean z, int i, Object obj) {
        super(0);
        this.a = i;
        this.c = obj;
        this.b = z;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r0v8, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                i iVar = (i) this.c;
                iVar.a = this.b;
                ?? r0 = iVar.c;
                if (r0 != 0) {
                    r0.invoke();
                }
                break;
            case 1:
                if (this.b) {
                    ((kotlin.jvm.internal.r) this.c).invoke();
                }
                break;
            default:
                ((Function1) this.c).invoke(Boolean.valueOf(!this.b));
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public f(boolean z, Function0 function0) {
        super(0);
        this.a = 1;
        this.b = z;
        this.c = (kotlin.jvm.internal.r) function0;
    }
}
