package androidx.compose.runtime.snapshots;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.snapshots.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0822b extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Function1 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0822b(Function1 function1, Function1 function12, int i) {
        super(1);
        this.a = i;
        this.b = function1;
        this.c = function12;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        long j;
        switch (this.a) {
            case 0:
                l lVar = (l) obj;
                synchronized (m.b) {
                    j = m.d;
                    m.d = 1 + j;
                }
                return new C0824d(j, lVar, this.b, this.c);
            case 1:
                this.b.invoke(obj);
                this.c.invoke(obj);
                return Unit.a;
            default:
                this.b.invoke(obj);
                this.c.invoke(obj);
                return Unit.a;
        }
    }
}
