package kotlinx.serialization.encoding;

import androidx.camera.camera2.internal.p0;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.f0;

/* loaded from: classes3.dex */
public interface a {
    p0 a();

    void b(SerialDescriptor serialDescriptor);

    short d(f0 f0Var, int i);

    float e(f0 f0Var, int i);

    char g(f0 f0Var, int i);

    long j(SerialDescriptor serialDescriptor, int i);

    byte k(f0 f0Var, int i);

    int n(SerialDescriptor serialDescriptor, int i);

    boolean q(SerialDescriptor serialDescriptor, int i);

    String r(SerialDescriptor serialDescriptor, int i);

    int t(SerialDescriptor serialDescriptor);

    Object v(SerialDescriptor serialDescriptor, int i, KSerializer kSerializer, Object obj);

    Decoder x(f0 f0Var, int i);

    double y(SerialDescriptor serialDescriptor, int i);

    Object z(SerialDescriptor serialDescriptor, int i, KSerializer kSerializer, Object obj);
}
