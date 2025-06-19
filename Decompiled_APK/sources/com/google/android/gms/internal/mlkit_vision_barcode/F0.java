package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.animation.C0285l;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.C1291m;
import com.comscore.streaming.ContentType;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public abstract class F0 {
    public static final /* synthetic */ int a = 0;
    public static final /* synthetic */ int b = 0;

    public static final void a(androidx.compose.foundation.layout.C c, C1291m c1291m, androidx.compose.material.e0 e0Var, androidx.compose.runtime.saveable.f fVar, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-771698376);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(c) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(c1291m) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(e0Var) : c0814p.h(e0Var) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(fVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i2 |= c0814p.h(function12) ? 131072 : 65536;
        }
        int i3 = i2;
        if (!c0814p.N(i3 & 1, (74899 & i3) != 74898)) {
            c0814p.Q();
        } else if (c1291m != null) {
            c0814p.X(-1197845889);
            boolean z = true;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function1, c0814p);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D(function12, c0814p);
            if ((i3 & 896) != 256 && ((i3 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 || !c0814p.h(e0Var))) {
                z = false;
            }
            boolean zF = z | c0814p.f(interfaceC0773a0D) | c0814p.h(c1291m) | c0814p.f(interfaceC0773a0D2);
            Object objI = c0814p.I();
            if (zF || objI == C0804k.a) {
                androidx.compose.material.navigation.m mVar = new androidx.compose.material.navigation.m(e0Var, c1291m, interfaceC0773a0D, interfaceC0773a0D2, null);
                c0814p.i0(mVar);
                objI = mVar;
            }
            C0776c.g(e0Var, c1291m, (Function2) objI, c0814p);
            com.google.android.gms.internal.mlkit_vision_camera.M1.a(c1291m, fVar, androidx.compose.runtime.internal.e.e(-2050060477, new androidx.compose.foundation.contextmenu.i(11, c1291m, c), c0814p), c0814p, ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | ((i3 >> 3) & 14) | 384);
            c0814p.p(false);
        } else {
            c0814p.X(-1196910836);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0285l(c, c1291m, e0Var, fVar, function1, function12, i);
        }
    }
}
