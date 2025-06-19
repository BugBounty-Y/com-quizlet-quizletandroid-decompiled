package kotlinx.serialization.descriptors;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public interface SerialDescriptor {
    String a();

    default boolean c() {
        return false;
    }

    int d(String str);

    U1 e();

    int f();

    String g(int i);

    default List getAnnotations() {
        return K.a;
    }

    List h(int i);

    SerialDescriptor i(int i);

    default boolean isInline() {
        return false;
    }

    boolean j(int i);
}
