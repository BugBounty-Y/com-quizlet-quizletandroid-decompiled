package kotlinx.serialization.json;

import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_camera.X1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class z implements KSerializer {
    public static final z a = new z();
    public static final kotlinx.serialization.descriptors.g b = T1.g("kotlinx.serialization.json.JsonPrimitive", kotlinx.serialization.descriptors.e.j, new SerialDescriptor[0], new com.sdk.growthbook.utils.a(24));

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        k kVarL = X1.d(decoder).l();
        if (kVarL instanceof y) {
            return (y) kVarL;
        }
        throw kotlinx.serialization.json.internal.k.d(-1, "Unexpected JSON element, expected JsonPrimitive, had " + K.a(kVarL.getClass()), kVarL.toString());
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return b;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        y value = (y) obj;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        X1.c(encoder);
        if (value instanceof JsonNull) {
            encoder.y(u.a, JsonNull.INSTANCE);
        } else {
            encoder.y(s.a, (r) value);
        }
    }
}
