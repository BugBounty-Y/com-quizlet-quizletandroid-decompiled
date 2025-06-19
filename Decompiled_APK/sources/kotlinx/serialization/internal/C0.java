package kotlinx.serialization.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class C0 implements KSerializer {
    public static final C0 a = new C0();
    public static final G b;

    static {
        Intrinsics.checkNotNullParameter(kotlin.jvm.internal.M.a, "<this>");
        b = AbstractC5047c0.a("kotlin.UShort", p0.a);
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return new kotlin.H(decoder.w(b).B());
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        short s = ((kotlin.H) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        encoder.x(b).f(s);
    }
}
