package kotlinx.serialization.internal;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u0 extends AbstractC5051e0 {
    public int[] a;
    public int b;

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final Object a() {
        int[] storage = Arrays.copyOf(this.a, this.b);
        Intrinsics.checkNotNullExpressionValue(storage, "copyOf(...)");
        Intrinsics.checkNotNullParameter(storage, "storage");
        return new kotlin.B(storage);
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final void b(int i) {
        int[] iArr = this.a;
        if (iArr.length < i) {
            int length = iArr.length * 2;
            if (i < length) {
                i = length;
            }
            int[] storage = Arrays.copyOf(iArr, i);
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
