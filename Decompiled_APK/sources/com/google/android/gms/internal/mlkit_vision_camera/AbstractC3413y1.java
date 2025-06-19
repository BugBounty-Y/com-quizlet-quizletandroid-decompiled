package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.y1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3413y1 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.lifecycle.A a2, androidx.lifecycle.J j, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-709389590);
        if (((i | 16 | (c0814p.h(function0) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            } else {
                c0814p.Q();
            }
            c0814p.q();
            if (a2 == androidx.lifecycle.A.ON_DESTROY) {
                throw new IllegalArgumentException("LifecycleEventEffect cannot be used to listen for Lifecycle.Event.ON_DESTROY, since Compose disposes of the composition before ON_DESTROY observers are invoked.");
            }
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function0, c0814p);
            boolean zF = c0814p.f(interfaceC0773a0D) | c0814p.h(j);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                objI = new androidx.lifecycle.compose.d(j, a2, interfaceC0773a0D, 0);
                c0814p.i0(objI);
            }
            C0776c.d(j, (Function1) objI, c0814p);
        }
        androidx.lifecycle.J j2 = j;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 0, a2, j2, function0);
        }
    }

    public static final int b(int i, int i2) {
        return (i >> i2) & 31;
    }
}
