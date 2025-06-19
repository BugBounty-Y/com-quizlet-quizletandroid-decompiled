package com.google.android.gms.internal.mlkit_vision_camera;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes2.dex */
public abstract class D1 {
    public static final /* synthetic */ int a = 0;

    public static kotlinx.coroutines.channels.h a(int i, int i2, kotlinx.coroutines.channels.a aVar) {
        if ((i2 & 1) != 0) {
            i = 0;
        }
        if ((i2 & 2) != 0) {
            aVar = kotlinx.coroutines.channels.a.a;
        }
        if (i == -2) {
            if (aVar != kotlinx.coroutines.channels.a.a) {
                return new kotlinx.coroutines.channels.r(1, aVar);
            }
            kotlinx.coroutines.channels.l.b1.getClass();
            return new kotlinx.coroutines.channels.h(kotlinx.coroutines.channels.k.b);
        }
        if (i != -1) {
            return i != 0 ? i != Integer.MAX_VALUE ? aVar == kotlinx.coroutines.channels.a.a ? new kotlinx.coroutines.channels.h(i) : new kotlinx.coroutines.channels.r(i, aVar) : new kotlinx.coroutines.channels.h(SubsamplingScaleImageView.TILE_SIZE_AUTO) : aVar == kotlinx.coroutines.channels.a.a ? new kotlinx.coroutines.channels.h(0) : new kotlinx.coroutines.channels.r(1, aVar);
        }
        if (aVar == kotlinx.coroutines.channels.a.a) {
            return new kotlinx.coroutines.channels.r(1, kotlinx.coroutines.channels.a.b);
        }
        throw new IllegalArgumentException("CONFLATED capacity cannot be used with non-default onBufferOverflow");
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00d7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.navigation.C1287i b(java.lang.String r8, kotlin.jvm.functions.Function1 r9) {
        /*
            Method dump skipped, instructions count: 308
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.D1.b(java.lang.String, kotlin.jvm.functions.Function1):androidx.navigation.i");
    }
}
