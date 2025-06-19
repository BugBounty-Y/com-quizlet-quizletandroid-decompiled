package kotlinx.serialization.encoding;

import androidx.camera.camera2.internal.p0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public interface Decoder {
    byte A();

    short B();

    float C();

    double D();

    p0 a();

    a c(SerialDescriptor serialDescriptor);

    boolean f();

    char h();

    int i(SerialDescriptor serialDescriptor);

    int m();

    String o();

    long p();

    boolean s();

    default Object u(KSerializer deserializer) {
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return deserializer.deserialize(this);
    }

    Decoder w(SerialDescriptor serialDescriptor);
}
