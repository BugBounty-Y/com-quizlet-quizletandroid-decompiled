package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4957p;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class w0 implements KSerializer {
    public static final w0 a = new w0();
    public static final G b;

    static {
        Intrinsics.checkNotNullParameter(C4957p.a, "<this>");
        b = AbstractC5047c0.a("kotlin.UInt", K.a);
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return new kotlin.A(decoder.w(b).m());
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        int i = ((kotlin.A) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        encoder.x(b).w(i);
    }
}
