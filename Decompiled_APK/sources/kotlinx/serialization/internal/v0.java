package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class v0 extends g0 {
    public static final v0 c;

    static {
        Intrinsics.checkNotNullParameter(kotlin.A.b, "<this>");
        c = new v0(w0.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        int[] collectionSize = ((kotlin.B) obj).a;
        Intrinsics.checkNotNullParameter(collectionSize, "$this$collectionSize");
        return collectionSize.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        u0 builder = (u0) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        int iM = decoder.x(this.b, i).m();
        kotlin.z zVar = kotlin.A.b;
        builder.getClass();
        builder.b(builder.d() + 1);
        int[] iArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        iArr[i2] = iM;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        int[] bufferWithData = ((kotlin.B) obj).a;
        Intrinsics.checkNotNullParameter(bufferWithData, "$this$toBuilder");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        u0 u0Var = new u0();
        u0Var.a = bufferWithData;
        u0Var.b = bufferWithData.length;
        u0Var.b(10);
        return u0Var;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new kotlin.B(kotlin.B.a(0));
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        int[] content = ((kotlin.B) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            Encoder encoderU = encoder.u(this.b, i2);
            int i3 = content[i2];
            kotlin.z zVar = kotlin.A.b;
            encoderU.w(i3);
        }
    }
}
