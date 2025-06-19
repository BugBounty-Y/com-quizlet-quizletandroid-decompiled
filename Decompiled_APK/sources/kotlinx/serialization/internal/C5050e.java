package kotlinx.serialization.internal;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.serialization.internal.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5050e extends AbstractC5051e0 {
    public boolean[] a;
    public int b;

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final Object a() {
        boolean[] zArrCopyOf = Arrays.copyOf(this.a, this.b);
        Intrinsics.checkNotNullExpressionValue(zArrCopyOf, "copyOf(...)");
        return zArrCopyOf;
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final void b(int i) {
        boolean[] zArr = this.a;
        if (zArr.length < i) {
            int length = zArr.length * 2;
            if (i < length) {
                i = length;
            }
            boolean[] zArrCopyOf = Arrays.copyOf(zArr, i);
            Intrinsics.checkNotNullExpressionValue(zArrCopyOf, "copyOf(...)");
            this.a = zArrCopyOf;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final int d() {
        return this.b;
    }
}
