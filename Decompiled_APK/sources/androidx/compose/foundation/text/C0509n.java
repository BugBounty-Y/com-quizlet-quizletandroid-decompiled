package androidx.compose.foundation.text;

import java.util.concurrent.atomic.AtomicLong;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.text.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0509n extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.foundation.text.selection.Z b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0509n(androidx.compose.foundation.text.selection.Z z, int i) {
        super(0);
        this.a = i;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                AtomicLong atomicLong = ((androidx.compose.foundation.text.selection.b0) this.b).d;
                long andIncrement = atomicLong.getAndIncrement();
                while (andIncrement == 0) {
                    andIncrement = atomicLong.getAndIncrement();
                }
                return Long.valueOf(andIncrement);
            default:
                AtomicLong atomicLong2 = ((androidx.compose.foundation.text.selection.b0) this.b).d;
                long andIncrement2 = atomicLong2.getAndIncrement();
                while (andIncrement2 == 0) {
                    andIncrement2 = atomicLong2.getAndIncrement();
                }
                return Long.valueOf(andIncrement2);
        }
    }
}
