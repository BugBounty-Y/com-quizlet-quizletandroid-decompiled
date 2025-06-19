package kotlinx.serialization.json;

import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class m implements KSerializer {
    public static final m a = new m();
    public static final kotlinx.serialization.descriptors.g b = T1.g("kotlinx.serialization.json.JsonElement", kotlinx.serialization.descriptors.c.c, new SerialDescriptor[0], new com.sdk.growthbook.utils.a(25));

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return X1.d(decoder).l();
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        k value = (k) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        X1.c(encoder);
        if (value instanceof y) {
            encoder.y(z.a, value);
        } else if (value instanceof v) {
            encoder.y(x.a, value);
        } else {
            if (!(value instanceof d)) {
                throw new NoWhenBranchMatchedException();
            }
            encoder.y(f.a, value);
        }
    }
}
