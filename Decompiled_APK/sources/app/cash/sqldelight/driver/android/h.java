package app.cash.sqldelight.driver.android;

import android.util.LruCache;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h extends LruCache {
    @Override // android.util.LruCache
    public final void entryRemoved(boolean z, Object obj, Object obj2, Object obj3) {
        ((Number) obj).intValue();
        j oldValue = (j) obj2;
        Intrinsics.checkNotNullParameter(oldValue, "oldValue");
        if (z) {
            oldValue.close();
        }
    }
}
