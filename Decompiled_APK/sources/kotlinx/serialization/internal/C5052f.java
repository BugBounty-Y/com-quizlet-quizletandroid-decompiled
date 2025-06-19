package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4943b;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.serialization.internal.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5052f extends g0 {
    public static final C5052f c;

    static {
        Intrinsics.checkNotNullParameter(C4943b.a, "<this>");
        c = new C5052f(C5053g.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        boolean[] zArr = (boolean[]) obj;
        Intrinsics.checkNotNullParameter(zArr, "<this>");
        return zArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        C5050e builder = (C5050e) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        boolean zQ = decoder.q(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        boolean[] zArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        zArr[i2] = zQ;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        boolean[] bufferWithData = (boolean[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        C5050e c5050e = new C5050e();
        c5050e.a = bufferWithData;
        c5050e.b = bufferWithData.length;
        c5050e.b(10);
        return c5050e;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new boolean[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        boolean[] content = (boolean[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.p(this.b, i2, content[i2]);
        }
    }
}
