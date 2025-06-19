package com.facebook.appevents.codeless;

import android.view.View;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final WeakReference a;
    public final String b;

    public e(View view, String viewMapKey) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(viewMapKey, "viewMapKey");
        this.a = new WeakReference(view);
        this.b = viewMapKey;
    }

    public final View a() {
        WeakReference weakReference = this.a;
        if (weakReference != null) {
            return (View) weakReference.get();
        }
        return null;
    }
}
