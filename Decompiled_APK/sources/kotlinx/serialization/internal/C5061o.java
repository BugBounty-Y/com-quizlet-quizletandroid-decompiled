package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4947f;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.serialization.internal.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5061o extends g0 {
    public static final C5061o c;

    static {
        Intrinsics.checkNotNullParameter(C4947f.a, "<this>");
        c = new C5061o(C5062p.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        char[] cArr = (char[]) obj;
        Intrinsics.checkNotNullParameter(cArr, "<this>");
        return cArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        C5060n builder = (C5060n) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        char cG = decoder.g(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        char[] cArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        cArr[i2] = cG;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        char[] bufferWithData = (char[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        C5060n c5060n = new C5060n();
        c5060n.a = bufferWithData;
        c5060n.b = bufferWithData.length;
        c5060n.b(10);
        return c5060n;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new char[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        char[] content = (char[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.h(this.b, i2, content[i2]);
        }
    }
}
