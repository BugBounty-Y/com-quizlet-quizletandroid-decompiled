package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4944c;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.serialization.internal.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5055i extends g0 {
    public static final C5055i c;

    static {
        Intrinsics.checkNotNullParameter(C4944c.a, "<this>");
        c = new C5055i(C5056j.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        byte[] bArr = (byte[]) obj;
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        return bArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        C5054h builder = (C5054h) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        byte bK = decoder.k(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        byte[] bArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        bArr[i2] = bK;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        byte[] bufferWithData = (byte[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        C5054h c5054h = new C5054h();
        c5054h.a = bufferWithData;
        c5054h.b = bufferWithData.length;
        c5054h.b(10);
        return c5054h;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new byte[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        byte[] content = (byte[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.o(this.b, i2, content[i2]);
        }
    }
}
