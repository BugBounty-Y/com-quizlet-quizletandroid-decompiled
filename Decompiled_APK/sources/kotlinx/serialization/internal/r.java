package kotlinx.serialization.internal;

import java.lang.ref.SoftReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends ClassValue {
    @Override // java.lang.ClassValue
    public final Object computeValue(Class type) {
        Intrinsics.checkNotNullParameter(type, "type");
        U u = new U();
        u.reference = new SoftReference<>(null);
        return u;
    }
}
