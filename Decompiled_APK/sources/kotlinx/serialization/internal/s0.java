package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class s0 extends g0 {
    public static final s0 c;

    static {
        Intrinsics.checkNotNullParameter(kotlin.x.b, "<this>");
        c = new s0(t0.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        byte[] collectionSize = ((kotlin.y) obj).a;
        Intrinsics.checkNotNullParameter(collectionSize, "$this$collectionSize");
        return collectionSize.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        r0 builder = (r0) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        byte bA = decoder.x(this.b, i).A();
        kotlin.w wVar = kotlin.x.b;
        builder.getClass();
        builder.b(builder.d() + 1);
        byte[] bArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        bArr[i2] = bA;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        byte[] bufferWithData = ((kotlin.y) obj).a;
        Intrinsics.checkNotNullParameter(bufferWithData, "$this$toBuilder");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        r0 r0Var = new r0();
        r0Var.a = bufferWithData;
        r0Var.b = bufferWithData.length;
        r0Var.b(10);
        return r0Var;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        byte[] storage = new byte[0];
        Intrinsics.checkNotNullParameter(storage, "storage");
        return new kotlin.y(storage);
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        byte[] content = ((kotlin.y) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            Encoder encoderU = encoder.u(this.b, i2);
            byte b = content[i2];
            kotlin.w wVar = kotlin.x.b;
            encoderU.j(b);
        }
    }
}
