package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class y0 extends g0 {
    public static final y0 c;

    static {
        Intrinsics.checkNotNullParameter(kotlin.D.b, "<this>");
        c = new y0(z0.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        long[] collectionSize = ((kotlin.E) obj).a;
        Intrinsics.checkNotNullParameter(collectionSize, "$this$collectionSize");
        return collectionSize.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        x0 builder = (x0) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        long jP = decoder.x(this.b, i).p();
        kotlin.C c2 = kotlin.D.b;
        builder.getClass();
        builder.b(builder.d() + 1);
        long[] jArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        jArr[i2] = jP;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        long[] bufferWithData = ((kotlin.E) obj).a;
        Intrinsics.checkNotNullParameter(bufferWithData, "$this$toBuilder");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        x0 x0Var = new x0();
        x0Var.a = bufferWithData;
        x0Var.b = bufferWithData.length;
        x0Var.b(10);
        return x0Var;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new kotlin.E(kotlin.E.a(0));
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        long[] content = ((kotlin.E) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            Encoder encoderU = encoder.u(this.b, i2);
            long j = content[i2];
            kotlin.C c2 = kotlin.D.b;
            encoderU.B(j);
        }
    }
}
