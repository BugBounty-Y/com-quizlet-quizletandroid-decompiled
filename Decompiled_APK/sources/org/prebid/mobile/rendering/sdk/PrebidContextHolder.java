package org.prebid.mobile.rendering.sdk;

import android.content.Context;
import java.lang.ref.WeakReference;

/* loaded from: classes3.dex */
public abstract class PrebidContextHolder {
    public static WeakReference a;

    public static Context a() {
        WeakReference weakReference = a;
        if (weakReference != null) {
            return (Context) weakReference.get();
        }
        return null;
    }
}
