package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4944c;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class t0 implements KSerializer {
    public static final t0 a = new t0();
    public static final G b;

    static {
        Intrinsics.checkNotNullParameter(C4944c.a, "<this>");
        b = AbstractC5047c0.a("kotlin.UByte", C5056j.a);
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return new kotlin.x(decoder.w(b).A());
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        byte b2 = ((kotlin.x) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        encoder.x(b).j(b2);
    }
}
