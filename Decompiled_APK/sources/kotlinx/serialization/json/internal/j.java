package kotlinx.serialization.json.internal;

import com.quizlet.search.composables.M;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.C5069x;

/* loaded from: classes3.dex */
public final class j {
    public final C5069x a;
    public boolean b;

    public j(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        this.a = new C5069x(descriptor, new M(2, this, j.class, "readIfAbsent", "readIfAbsent(Lkotlinx/serialization/descriptors/SerialDescriptor;I)Z", 0, 1));
    }
}
