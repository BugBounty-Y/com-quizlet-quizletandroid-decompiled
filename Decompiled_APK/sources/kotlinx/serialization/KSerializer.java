package kotlinx.serialization;

import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public interface KSerializer {
    Object deserialize(Decoder decoder);

    SerialDescriptor getDescriptor();

    void serialize(Encoder encoder, Object obj);
}
