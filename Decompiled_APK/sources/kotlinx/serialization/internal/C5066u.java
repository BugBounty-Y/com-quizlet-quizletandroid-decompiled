package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4951j;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.serialization.internal.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5066u extends g0 {
    public static final C5066u c;

    static {
        Intrinsics.checkNotNullParameter(C4951j.a, "<this>");
        c = new C5066u(C5067v.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        double[] dArr = (double[]) obj;
        Intrinsics.checkNotNullParameter(dArr, "<this>");
        return dArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        C5065t builder = (C5065t) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        double dY = decoder.y(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        double[] dArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        dArr[i2] = dY;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        double[] bufferWithData = (double[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        C5065t c5065t = new C5065t();
        c5065t.a = bufferWithData;
        c5065t.b = bufferWithData.length;
        c5065t.b(10);
        return c5065t;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new double[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        double[] content = (double[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.A(this.b, i2, content[i2]);
        }
    }
}
