package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Build;
import android.view.ViewGroup;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.m2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3367m2 {
    public static boolean a = true;
    public static final /* synthetic */ int b = 0;

    public static final boolean a(String method) {
        Intrinsics.checkNotNullParameter(method, "method");
        return (Intrinsics.b(method, "GET") || Intrinsics.b(method, "HEAD")) ? false : true;
    }

    public static void b(ViewGroup viewGroup, boolean z) {
        if (Build.VERSION.SDK_INT >= 29) {
            androidx.transition.K.b(viewGroup, z);
        } else if (a) {
            try {
                androidx.transition.K.b(viewGroup, z);
            } catch (NoSuchMethodError unused) {
                a = false;
            }
        }
    }
}
