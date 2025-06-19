package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.jvm.internal.C4952k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B extends g0 {
    public static final B c;

    static {
        R1.f(C4952k.a);
        c = new B(C.a);
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final int d(Object obj) {
        float[] fArr = (float[]) obj;
        Intrinsics.checkNotNullParameter(fArr, "<this>");
        return fArr.length;
    }

    @Override // kotlinx.serialization.internal.AbstractC5064s, kotlinx.serialization.internal.AbstractC5042a
    public final void f(kotlinx.serialization.encoding.a decoder, int i, Object obj) {
        A builder = (A) obj;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Intrinsics.checkNotNullParameter(builder, "builder");
        float fE = decoder.e(this.b, i);
        builder.getClass();
        builder.b(builder.d() + 1);
        float[] fArr = builder.a;
        int i2 = builder.b;
        builder.b = i2 + 1;
        fArr[i2] = fE;
    }

    @Override // kotlinx.serialization.internal.AbstractC5042a
    public final Object g(Object obj) {
        float[] bufferWithData = (float[]) obj;
        Intrinsics.checkNotNullParameter(bufferWithData, "<this>");
        Intrinsics.checkNotNullParameter(bufferWithData, "bufferWithData");
        A a = new A();
        a.a = bufferWithData;
        a.b = bufferWithData.length;
        a.b(10);
        return a;
    }

    @Override // kotlinx.serialization.internal.g0
    public final Object j() {
        return new float[0];
    }

    @Override // kotlinx.serialization.internal.g0
    public final void k(kotlinx.serialization.encoding.b encoder, Object obj, int i) {
        float[] content = (float[]) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(content, "content");
        for (int i2 = 0; i2 < i; i2++) {
            encoder.t(this.b, i2, content[i2]);
        }
    }
}
