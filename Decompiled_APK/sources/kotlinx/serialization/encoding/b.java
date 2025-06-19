package kotlinx.serialization.encoding;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.f0;

/* loaded from: classes3.dex */
public interface b {
    void A(SerialDescriptor serialDescriptor, int i, double d);

    void C(SerialDescriptor serialDescriptor, int i, long j);

    default boolean D(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return true;
    }

    void b(SerialDescriptor serialDescriptor);

    void g(f0 f0Var, int i, short s);

    void h(f0 f0Var, int i, char c);

    void i(SerialDescriptor serialDescriptor, int i, KSerializer kSerializer, Object obj);

    void l(int i, int i2, SerialDescriptor serialDescriptor);

    void o(f0 f0Var, int i, byte b);

    void p(SerialDescriptor serialDescriptor, int i, boolean z);

    void r(SerialDescriptor serialDescriptor, int i, String str);

    void s(SerialDescriptor serialDescriptor, int i, KSerializer kSerializer, Object obj);

    void t(f0 f0Var, int i, float f);

    Encoder u(f0 f0Var, int i);
}
