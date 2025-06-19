package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4957p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J extends g0 {
    public static final J c;

    static {
        Intrinsics.checkNotNullParameter(C4957p.a, "<this>");
        c = new J(K.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        int[] iArr = (int[]) obj;
        Intrinsics.checkNotNullParameter(iArr, "<this>");
        return iArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        I builder = (I) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        int iN = decoder.n(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        int[] iArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        iArr[i2] = iN;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        int[] bufferWithData = (int[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        I i = new I();
        i.a = bufferWithData;
        i.b = bufferWithData.length;
        i.b(10);
        return i;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new int[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        int[] content = (int[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.l(i2, content[i2], this.b);
        }
    }
}
