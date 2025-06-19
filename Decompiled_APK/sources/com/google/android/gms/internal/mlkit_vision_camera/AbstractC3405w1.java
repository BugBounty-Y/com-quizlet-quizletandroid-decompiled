package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import android.content.ContextWrapper;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.InterfaceC1261w;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.AbstractC4966e;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.w1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3405w1 {
    public static final /* synthetic */ int a = 0;

    public static final void a(int i, String str) {
        if (str.charAt(i) == '-') {
            return;
        }
        throw new IllegalArgumentException(("Expected '-' (hyphen) at index 8, but was " + str.charAt(i)).toString());
    }

    public static final void b(long j, byte[] bArr, int i, int i2) {
        int i3 = (i2 * 2) + i;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = AbstractC4966e.a[(int) (255 & j)];
            bArr[i3 - 1] = (byte) i5;
            i3 -= 2;
            bArr[i3] = (byte) (i5 >> 8);
            j >>= 8;
        }
    }

    public static final dagger.hilt.android.internal.lifecycle.f c(androidx.lifecycle.C0 c0, InterfaceC0806l interfaceC0806l) {
        dagger.hilt.android.internal.lifecycle.f fVarD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Y(1770922558);
        if (c0 instanceof InterfaceC1261w) {
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            androidx.lifecycle.y0 delegateFactory = ((InterfaceC1261w) c0).getDefaultViewModelProviderFactory();
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(delegateFactory, "delegateFactory");
            while (context instanceof ContextWrapper) {
                if (context instanceof androidx.activity.s) {
                    fVarD = dagger.hilt.android.internal.lifecycle.f.d((androidx.activity.s) context, delegateFactory);
                    Intrinsics.checkNotNullExpressionValue(fVarD, "createInternal(\n        … */ delegateFactory\n    )");
                } else {
                    context = ((ContextWrapper) context).getBaseContext();
                    Intrinsics.checkNotNullExpressionValue(context, "ctx.baseContext");
                }
            }
            throw new IllegalStateException("Expected an activity context for creating a HiltViewModelFactory but instead found: " + context);
        }
        fVarD = null;
        c0814p.p(false);
        return fVarD;
    }
}
