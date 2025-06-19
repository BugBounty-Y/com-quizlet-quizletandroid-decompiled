package kotlinx.coroutines.internal;

import java.util.Arrays;
import java.util.List;
import java.util.ServiceConfigurationError;

/* loaded from: classes3.dex */
public abstract class e {
    public static final List a;

    static {
        try {
            a = kotlin.sequences.q.j(kotlin.sequences.n.b(Arrays.asList(new kotlinx.coroutines.android.b()).iterator()));
        } catch (Throwable th) {
            throw new ServiceConfigurationError(th.getMessage(), th);
        }
    }
}
