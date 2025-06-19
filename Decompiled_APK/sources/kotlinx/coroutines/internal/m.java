package kotlinx.coroutines.internal;

import android.os.Looper;
import java.util.Arrays;
import java.util.Iterator;
import java.util.ServiceConfigurationError;

/* loaded from: classes3.dex */
public abstract class m {
    public static final kotlinx.coroutines.android.d a;

    static {
        String property;
        int i = s.a;
        Object next = null;
        try {
            property = System.getProperty("kotlinx.coroutines.fast.service.loader");
        } catch (SecurityException unused) {
            property = null;
        }
        if (property != null) {
            Boolean.parseBoolean(property);
        }
        try {
            Iterator it2 = kotlin.sequences.q.j(kotlin.sequences.n.b(Arrays.asList(new kotlinx.coroutines.android.a()).iterator())).iterator();
            if (it2.hasNext()) {
                next = it2.next();
                if (it2.hasNext()) {
                    ((kotlinx.coroutines.android.a) next).getClass();
                    do {
                        ((kotlinx.coroutines.android.a) it2.next()).getClass();
                    } while (it2.hasNext());
                }
            }
            if (((kotlinx.coroutines.android.a) next) == null) {
                throw new IllegalStateException("Module with the Main dispatcher is missing. Add dependency providing the Main dispatcher, e.g. 'kotlinx-coroutines-android' and ensure it has the same version as 'kotlinx-coroutines-core'");
            }
            Looper mainLooper = Looper.getMainLooper();
            if (mainLooper == null) {
                throw new IllegalStateException("The main looper is not available");
            }
            a = new kotlinx.coroutines.android.d(kotlinx.coroutines.android.e.a(mainLooper));
        } catch (Throwable th) {
            throw new ServiceConfigurationError(th.getMessage(), th);
        }
    }
}
