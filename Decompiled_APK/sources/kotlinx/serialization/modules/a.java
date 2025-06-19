package kotlinx.serialization.modules;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.q0;

/* loaded from: classes3.dex */
public final class a extends c {
    @Override // kotlinx.serialization.modules.c
    public final KSerializer a(List typeArgumentsSerializers) {
        Intrinsics.checkNotNullParameter(typeArgumentsSerializers, "typeArgumentsSerializers");
        return q0.a;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof a)) {
            return false;
        }
        ((a) obj).getClass();
        Object obj2 = q0.a;
        return obj2.equals(obj2);
    }

    public final int hashCode() {
        return q0.a.hashCode();
    }
}
