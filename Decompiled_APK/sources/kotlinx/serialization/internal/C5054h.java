package kotlinx.serialization.internal;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.serialization.internal.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5054h extends AbstractC5051e0 {
    public byte[] a;
    public int b;

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final Object a() {
        byte[] bArrCopyOf = Arrays.copyOf(this.a, this.b);
        Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(...)");
        return bArrCopyOf;
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final void b(int i) {
        byte[] bArr = this.a;
        if (bArr.length < i) {
            int length = bArr.length * 2;
            if (i < length) {
                i = length;
            }
            byte[] bArrCopyOf = Arrays.copyOf(bArr, i);
            Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(...)");
            this.a = bArrCopyOf;
        }
    }

    @Override // kotlinx.serialization.internal.AbstractC5051e0
    public final int d() {
        return this.b;
    }
}
