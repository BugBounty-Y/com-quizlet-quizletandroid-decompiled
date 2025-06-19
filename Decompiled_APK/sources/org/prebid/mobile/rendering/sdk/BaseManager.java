package org.prebid.mobile.rendering.sdk;

import android.content.Context;
import java.lang.ref.WeakReference;

/* loaded from: classes3.dex */
public class BaseManager {
    public final WeakReference a;

    public BaseManager(Context context) {
        if (context != null) {
            this.a = new WeakReference(context);
        }
    }

    public final Context a() {
        WeakReference weakReference = this.a;
        if (weakReference != null) {
            return (Context) weakReference.get();
        }
        return null;
    }
}
