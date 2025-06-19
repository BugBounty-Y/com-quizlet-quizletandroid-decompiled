package kotlinx.serialization.internal;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x0 extends AbstractC5051e0 {
    public long[] a;
    public int b;

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final Object a() {
        long[] storage = Arrays.copyOf(this.a, this.b);
        Intrinsics.checkNotNullExpressionValue(storage, "copyOf(...)");
        Intrinsics.checkNotNullParameter(storage, "storage");
        return new kotlin.E(storage);
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final void b(int i) {
        long[] jArr = this.a;
        if (jArr.length < i) {
            int length = jArr.length * 2;
            if (i < length) {
                i = length;
            }
            long[] storage = Arrays.copyOf(jArr, i);
            Intrinsics.checkNotNullExpressionValue(storage, "copyOf(...)");
            Intrinsics.checkNotNullParameter(storage, "storage");
            this.a = storage;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final int d() {
        return this.b;
    }
}
