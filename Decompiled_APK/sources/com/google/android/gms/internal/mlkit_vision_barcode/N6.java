package com.google.android.gms.internal.mlkit_vision_barcode;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class N6 {
    public static final androidx.datastore.core.k0 a(String filePath) {
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        return new androidx.datastore.core.k0(filePath);
    }

    public static Application b(Context context) {
        if (context instanceof Application) {
            return (Application) context;
        }
        Context baseContext = context;
        while (baseContext instanceof ContextWrapper) {
            baseContext = ((ContextWrapper) baseContext).getBaseContext();
            if (baseContext instanceof Application) {
                return (Application) baseContext;
            }
        }
        throw new IllegalStateException("Could not find an Application in the given context: " + context);
    }
}
