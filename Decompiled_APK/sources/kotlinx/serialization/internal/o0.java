package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o0 extends g0 {
    public static final o0 c;

    static {
        Intrinsics.checkNotNullParameter(kotlin.jvm.internal.M.a, "<this>");
        c = new o0(p0.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        short[] sArr = (short[]) obj;
        Intrinsics.checkNotNullParameter(sArr, "<this>");
        return sArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        n0 builder = (n0) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        short sD = decoder.d(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        short[] sArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        sArr[i2] = sD;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        short[] bufferWithData = (short[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        n0 n0Var = new n0();
        n0Var.a = bufferWithData;
        n0Var.b = bufferWithData.length;
        n0Var.b(10);
        return n0Var;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new short[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        short[] content = (short[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.g(this.b, i2, content[i2]);
        }
    }
}
