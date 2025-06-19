package kotlinx.serialization.internal;

import java.lang.ref.SoftReference;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class U {

    @NotNull
    public volatile SoftReference<Object> reference;

    public final synchronized Object a(Function0 factory) {
        Intrinsics.checkNotNullParameter(factory, "factory");
        Object obj = this.reference.get();
        if (obj != null) {
            return obj;
        }
        Object objInvoke = factory.invoke();
        this.reference = new SoftReference<>(objInvoke);
        return objInvoke;
    }
}
