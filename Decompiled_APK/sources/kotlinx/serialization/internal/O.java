package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4959s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class O extends g0 {
    public static final O c;

    static {
        Intrinsics.checkNotNullParameter(C4959s.a, "<this>");
        c = new O(P.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        long[] jArr = (long[]) obj;
        Intrinsics.checkNotNullParameter(jArr, "<this>");
        return jArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        N builder = (N) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        long j = decoder.j(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        long[] jArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        jArr[i2] = j;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        long[] bufferWithData = (long[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        N n = new N();
        n.a = bufferWithData;
        n.b = bufferWithData.length;
        n.b(10);
        return n;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new long[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        long[] content = (long[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.C(this.b, i2, content[i2]);
        }
    }
}
