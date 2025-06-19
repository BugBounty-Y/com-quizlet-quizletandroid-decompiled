package kotlinx.serialization.json;

import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.json.internal.JsonDecodingException;

/* loaded from: classes3.dex */
public final class u implements KSerializer {
    public static final u a = new u();
    public static final kotlinx.serialization.descriptors.g b = T1.g("kotlinx.serialization.json.JsonNull", kotlinx.serialization.descriptors.i.b, new SerialDescriptor[0], new com.sdk.growthbook.utils.a(24));

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        X1.d(decoder);
        if (!decoder.s()) {
            return JsonNull.INSTANCE;
        }
        Intrinsics.checkNotNullParameter("Expected 'null' literal", "message");
        Intrinsics.checkNotNullParameter("Expected 'null' literal", "message");
        throw new JsonDecodingException("Expected 'null' literal");
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        JsonNull value = (JsonNull) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        X1.c(encoder);
        encoder.d();
    }
}
