package androidx.work;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class S extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Worker b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ S(Worker worker, int i) {
        super(0);
        this.a = i;
        this.b = worker;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.getForegroundInfo();
            default:
                return this.b.doWork();
        }
    }
}
