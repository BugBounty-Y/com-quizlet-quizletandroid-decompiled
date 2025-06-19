package com.bumptech.glide.util;

/* loaded from: classes.dex */
public abstract class f {
    public static final androidx.camera.core.impl.utils.executor.a a = new androidx.camera.core.impl.utils.executor.a(3);
    public static final androidx.camera.core.impl.utils.executor.a b = new androidx.camera.core.impl.utils.executor.a(4);

    public static void a(String str, boolean z) {
        if (!z) {
            throw new IllegalArgumentException(str);
        }
    }

    public static void b(Object obj) {
        c(obj, "Argument must not be null");
    }

    public static void c(Object obj, String str) {
        if (obj == null) {
            throw new NullPointerException(str);
        }
    }
}
