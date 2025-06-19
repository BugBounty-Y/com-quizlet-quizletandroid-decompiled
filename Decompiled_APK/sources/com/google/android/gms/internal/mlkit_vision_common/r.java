package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class r {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x03c9  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x03cf  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x040e  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x06ae  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x01ad  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01cc  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0274  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0278  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0293  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x02a4  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x02ad  */
    /* JADX WARN: Type inference failed for: r8v16 */
    /* JADX WARN: Type inference failed for: r8v3 */
    /* JADX WARN: Type inference failed for: r8v4, types: [boolean, int] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.features.setpage.header.data.d r45, androidx.compose.ui.n r46, kotlin.jvm.functions.Function1 r47, kotlin.jvm.functions.Function0 r48, kotlin.jvm.functions.Function0 r49, kotlin.jvm.functions.Function0 r50, kotlin.jvm.functions.Function0 r51, kotlin.jvm.functions.Function0 r52, kotlin.jvm.functions.Function0 r53, kotlin.jvm.functions.Function0 r54, androidx.compose.runtime.InterfaceC0806l r55, int r56) {
        /*
            Method dump skipped, instructions count: 1756
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.r.a(com.quizlet.features.setpage.header.data.d, androidx.compose.ui.n, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x010b A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(android.content.Context r14, com.airbnb.lottie.compose.o r15, java.lang.String r16, java.lang.String r17, java.lang.String r18, java.lang.String r19, kotlin.coroutines.jvm.internal.c r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.r.b(android.content.Context, com.airbnb.lottie.compose.o, java.lang.String, java.lang.String, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final com.airbnb.lottie.A c(Context context, com.airbnb.lottie.compose.o oVar, String str) {
        if (oVar == null) {
            throw new NoWhenBranchMatchedException();
        }
        if (!Intrinsics.b(str, "__LottieInternalDefaultCacheKey__")) {
            return com.airbnb.lottie.l.f(context, str, oVar.a);
        }
        int i = oVar.a;
        return com.airbnb.lottie.l.f(context, com.airbnb.lottie.l.l(context, i), i);
    }

    public static final com.airbnb.lottie.compose.n d(com.airbnb.lottie.compose.o spec, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(spec, "spec");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Y(-1248473602);
        androidx.compose.foundation.gestures.S s = new androidx.compose.foundation.gestures.S(3, 4, null);
        Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        c0814p.Y(1388713953);
        boolean zF = c0814p.f(spec);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (zF || objI == v) {
            objI = C0776c.z(new com.airbnb.lottie.compose.n());
            c0814p.i0(objI);
        }
        InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
        c0814p.p(false);
        c0814p.Y(1388714244);
        boolean zF2 = c0814p.f(spec) | c0814p.f("__LottieInternalDefaultCacheKey__");
        Object objI2 = c0814p.I();
        if (zF2 || objI2 == v) {
            objI2 = c(context, spec, "__LottieInternalDefaultCacheKey__");
            c0814p.i0(objI2);
        }
        c0814p.p(false);
        C0776c.g(spec, "__LottieInternalDefaultCacheKey__", new com.airbnb.lottie.compose.t(s, context, spec, interfaceC0773a0, null), c0814p);
        com.airbnb.lottie.compose.n nVar = (com.airbnb.lottie.compose.n) interfaceC0773a0.getValue();
        c0814p.p(false);
        return nVar;
    }
}
