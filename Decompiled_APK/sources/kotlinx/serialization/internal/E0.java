package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.AbstractC4966e;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class E0 implements KSerializer {
    public static final E0 a = new E0();
    public static final h0 b = new h0("kotlin.uuid.Uuid", kotlinx.serialization.descriptors.e.j);

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        String uuidString = decoder.o();
        Intrinsics.checkNotNullParameter(uuidString, "uuidString");
        if (uuidString.length() != 36) {
            throw new IllegalArgumentException("Expected a 36-char string in the standard uuid format.");
        }
        long jB = AbstractC4966e.b(0, 8, uuidString);
        AbstractC3405w1.a(8, uuidString);
        long jB2 = AbstractC4966e.b(9, 13, uuidString);
        AbstractC3405w1.a(13, uuidString);
        long jB3 = AbstractC4966e.b(14, 18, uuidString);
        AbstractC3405w1.a(18, uuidString);
        long jB4 = AbstractC4966e.b(19, 23, uuidString);
        AbstractC3405w1.a(23, uuidString);
        long j = (jB << 32) | (jB2 << 16) | jB3;
        long jB5 = AbstractC4966e.b(24, 36, uuidString) | (jB4 << 48);
        return (j == 0 && jB5 == 0) ? kotlin.uuid.a.d : new kotlin.uuid.a(j, jB5);
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        kotlin.uuid.a value = (kotlin.uuid.a) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        encoder.E(value.toString());
    }
}
