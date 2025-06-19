package androidx.compose.ui.graphics.colorspace;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class p extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(q qVar, int i) {
        super(1);
        this.a = i;
        this.b = qVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                double dDoubleValue = ((Number) obj).doubleValue();
                return Double.valueOf(this.b.n.d(kotlin.ranges.l.a(dDoubleValue, r10.e, r10.f)));
            default:
                return Double.valueOf(kotlin.ranges.l.a(this.b.k.d(((Number) obj).doubleValue()), r10.e, r10.f));
        }
    }
}
