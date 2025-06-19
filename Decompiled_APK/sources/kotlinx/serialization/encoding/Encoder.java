package kotlinx.serialization.encoding;

import androidx.camera.camera2.internal.p0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public interface Encoder {
    void B(long j);

    void E(String str);

    p0 a();

    b c(SerialDescriptor serialDescriptor);

    void d();

    void e(double d);

    void f(short s);

    void j(byte b);

    void k(boolean z);

    void m(float f);

    void n(char c);

    default void q(KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        if (serializer.getDescriptor().c()) {
            y(serializer, obj);
        } else if (obj == null) {
            d();
        } else {
            y(serializer, obj);
        }
    }

    void v(SerialDescriptor serialDescriptor, int i);

    void w(int i);

    Encoder x(SerialDescriptor serialDescriptor);

    default void y(KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        serializer.serialize(this, obj);
    }

    default b z(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return c(descriptor);
    }
}
