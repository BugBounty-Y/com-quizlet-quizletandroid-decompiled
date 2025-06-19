package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.T1;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes3.dex */
public final class T implements KSerializer {
    public final KSerializer a;
    public final KSerializer b;
    public final /* synthetic */ int c;
    public final kotlinx.serialization.descriptors.g d;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public T(KSerializer keySerializer, KSerializer valueSerializer, int i) {
        this(keySerializer, valueSerializer, (byte) 0);
        this.c = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(keySerializer, "keySerializer");
                Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
                this(keySerializer, valueSerializer, (byte) 0);
                this.d = T1.f("kotlin.Pair", new SerialDescriptor[0], new Q(keySerializer, valueSerializer, 1));
                break;
            default:
                Intrinsics.checkNotNullParameter(keySerializer, "keySerializer");
                Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
                this.d = T1.g("kotlin.collections.Map.Entry", kotlinx.serialization.descriptors.j.d, new SerialDescriptor[0], new Q(keySerializer, valueSerializer, 0));
                break;
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final Object deserialize(Decoder decoder) {
        Object s;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor);
        Object obj = AbstractC5047c0.c;
        Object objZ = obj;
        Object objZ2 = objZ;
        while (true) {
            int iT = aVarC.t(getDescriptor());
            if (iT == -1) {
                if (objZ == obj) {
                    throw new SerializationException("Element 'key' is missing");
                }
                if (objZ2 == obj) {
                    throw new SerializationException("Element 'value' is missing");
                }
                switch (this.c) {
                    case 0:
                        s = new S(objZ, objZ2);
                        break;
                    default:
                        s = new Pair(objZ, objZ2);
                        break;
                }
                aVarC.b(descriptor);
                return s;
            }
            if (iT == 0) {
                objZ = aVarC.z(getDescriptor(), 0, this.a, null);
            } else {
                if (iT != 1) {
                    throw new SerializationException(android.support.v4.media.session.a.f(iT, "Invalid index: "));
                }
                objZ2 = aVarC.z(getDescriptor(), 1, this.b, null);
            }
        }
    }

    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        switch (this.c) {
        }
        return this.d;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(Encoder encoder, Object obj) {
        Object key;
        Object value;
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        kotlinx.serialization.encoding.b bVarC = encoder.c(getDescriptor());
        SerialDescriptor descriptor = getDescriptor();
        switch (this.c) {
            case 0:
                Map.Entry entry = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(entry, "<this>");
                key = entry.getKey();
                break;
            default:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<this>");
                key = pair.a;
                break;
        }
        bVarC.i(descriptor, 0, this.a, key);
        SerialDescriptor descriptor2 = getDescriptor();
        switch (this.c) {
            case 0:
                Map.Entry entry2 = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(entry2, "<this>");
                value = entry2.getValue();
                break;
            default:
                Pair pair2 = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair2, "<this>");
                value = pair2.b;
                break;
        }
        bVarC.i(descriptor2, 1, this.b, value);
        bVarC.b(getDescriptor());
    }

    public T(KSerializer kSerializer, KSerializer kSerializer2, byte b) {
        this.a = kSerializer;
        this.b = kSerializer2;
    }
}
