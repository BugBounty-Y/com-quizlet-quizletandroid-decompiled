package kotlinx.serialization.internal;

import kotlin.jvm.internal.C4959s;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class z0 implements KSerializer {
    public static final z0 a = new z0();
    public static final G b;

    static {
        Intrinsics.checkNotNullParameter(C4959s.a, "<this>");
        b = AbstractC5047c0.a("kotlin.ULong", P.a);
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return new kotlin.D(decoder.w(b).p());
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        long j = ((kotlin.D) obj).a;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        encoder.x(b).B(j);
    }
}
