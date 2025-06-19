package kotlinx.serialization.json.internal;

import java.util.Set;
import kotlin.A;
import kotlin.D;
import kotlin.H;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.C0;
import kotlinx.serialization.internal.t0;
import kotlinx.serialization.internal.w0;
import kotlinx.serialization.internal.z0;

/* loaded from: classes3.dex */
public abstract class w {
    public static final Set a;

    static {
        Intrinsics.checkNotNullParameter(A.b, "<this>");
        Intrinsics.checkNotNullParameter(D.b, "<this>");
        Intrinsics.checkNotNullParameter(kotlin.x.b, "<this>");
        Intrinsics.checkNotNullParameter(H.b, "<this>");
        SerialDescriptor[] elements = {w0.b, z0.b, t0.b, C0.b};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
    }

    public static final boolean a(SerialDescriptor serialDescriptor) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        return serialDescriptor.isInline() && a.contains(serialDescriptor);
    }
}
