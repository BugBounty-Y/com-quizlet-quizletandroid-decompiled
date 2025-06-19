package androidx.collection;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ J b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ T(J j, int i) {
        super(1);
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return obj == this.b ? "(this)" : String.valueOf(obj);
            default:
                if (obj instanceof androidx.compose.runtime.snapshots.A) {
                    ((androidx.compose.runtime.snapshots.A) obj).h(4);
                }
                this.b.a(obj);
                return Unit.a;
        }
    }
}
