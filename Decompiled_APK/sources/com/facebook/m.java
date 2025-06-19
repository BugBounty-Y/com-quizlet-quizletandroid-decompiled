package com.facebook;

import android.content.Context;
import java.util.concurrent.Callable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements Callable {
    @Override // java.util.concurrent.Callable
    public final Object call() {
        Context context = o.h;
        if (context != null) {
            return context.getCacheDir();
        }
        Intrinsics.m("applicationContext");
        throw null;
    }
}
