package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class B0 extends g0 {
    public static final B0 c;

    static {
        Intrinsics.checkNotNullParameter(kotlin.H.b, "<this>");
        c = new B0(C0.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        short[] collectionSize = ((kotlin.I) obj).a;
        Intrinsics.checkNotNullParameter(collectionSize, "$this$collectionSize");
        return collectionSize.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        A0 builder = (A0) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        short sB = decoder.x(this.b, i).B();
        kotlin.G g = kotlin.H.b;
        builder.getClass();
        builder.b(builder.d() + 1);
        short[] sArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        sArr[i2] = sB;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        short[] bufferWithData = ((kotlin.I) obj).a;
        Intrinsics.checkNotNullParameter(bufferWithData, "$this$toBuilder");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        A0 a0 = new A0();
        a0.a = bufferWithData;
        a0.b = bufferWithData.length;
        a0.b(10);
        return a0;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        short[] storage = new short[0];
        Intrinsics.checkNotNullParameter(storage, "storage");
        return new kotlin.I(storage);
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        short[] content = ((kotlin.I) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            Encoder encoderU = encoder.u(this.b, i2);
            short s = content[i2];
            kotlin.G g = kotlin.H.b;
            encoderU.f(s);
        }
    }
}
