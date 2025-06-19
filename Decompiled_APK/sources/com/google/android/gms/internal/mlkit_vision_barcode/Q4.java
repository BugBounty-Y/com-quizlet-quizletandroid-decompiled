package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.quizlet.features.folders.data.C4314w0;
import com.quizlet.features.folders.data.InterfaceC4318y0;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Q4 {
    public static final void a(com.quizlet.ui.models.content.listitem.o oVar, int i, Function1 function1, androidx.compose.foundation.lazy.A a, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-563266651);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.h(oVar) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.d(i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.f(a) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p.h(dVar) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            String strJ = j(oVar);
            c0814p.X(1744942245);
            boolean zH = ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i3 & 896) == 256) | c0814p.h(oVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.folders.composables.K(function1, oVar, i, 1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            P5.a(strJ, (Function0) objI, new com.quizlet.ui.compose.util.a(true, a, null, 4), androidx.compose.runtime.internal.e.e(2117047883, new com.quizlet.assembly.compose.input.f(dVar, 7), c0814p), c0814p, 3072);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.F(oVar, i, function1, a, dVar, i2);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2131650128);
        if ((((c0814p2.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.v();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.l;
            mVar.s();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.recommendations), AbstractC0382e.y(qVar, f, f2, DefinitionKt.NO_Float_VALUE, f, 4), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).i, c0814p, 0, 0, 65532);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 5, qVar);
        }
    }

    public static final long c(float f, float f2) {
        return (Float.floatToRawIntBits(f2) & 4294967295L) | (Float.floatToRawIntBits(f) << 32);
    }

    public static final void d(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(635474979);
        if ((((c0814p2.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            String strD = AbstractC3106b5.d(c0814p2, R.string.what_others_are_studying);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).i;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.v();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.l;
            mVar.s();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.y(qVar, f, f2, DefinitionKt.NO_Float_VALUE, f, 4), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65532);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 4, qVar);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable e(com.mayakapps.kache.InterfaceC4032a r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof com.quizlet.shared.cache.k
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.shared.cache.k r0 = (com.quizlet.shared.cache.k) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            com.quizlet.shared.cache.k r0 = new com.quizlet.shared.cache.k
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3b
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.k = r3
            java.lang.Object r5 = r4.b(r0)
            if (r5 != r1) goto L3b
            return r1
        L3b:
            com.mayakapps.kache.w r5 = (com.mayakapps.kache.w) r5
            java.lang.String r4 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r4)
            java.util.Set r4 = r5.a
            java.util.Set r5 = r5.b
            java.lang.Iterable r5 = (java.lang.Iterable) r5
            java.util.LinkedHashSet r4 = kotlin.collections.b0.f(r4, r5)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.Q4.e(com.mayakapps.kache.a, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable f(com.mayakapps.kache.u r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof com.quizlet.shared.cache.l
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.shared.cache.l r0 = (com.quizlet.shared.cache.l) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            com.quizlet.shared.cache.l r0 = new com.quizlet.shared.cache.l
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3b
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.k = r3
            java.lang.Object r5 = r4.d(r0)
            if (r5 != r1) goto L3b
            return r1
        L3b:
            com.mayakapps.kache.w r5 = (com.mayakapps.kache.w) r5
            java.lang.String r4 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r4)
            java.util.Set r4 = r5.a
            java.util.Set r5 = r5.b
            java.lang.Iterable r5 = (java.lang.Iterable) r5
            java.util.LinkedHashSet r4 = kotlin.collections.b0.f(r4, r5)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.Q4.f(com.mayakapps.kache.u, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public static final boolean g(long j) {
        long j2 = (j & 9187343241974906880L) ^ 9187343241974906880L;
        return (((~j2) & (j2 - 4294967297L)) & (-9223372034707292160L)) == 0;
    }

    public static final boolean h(long j) {
        return (j & 9223372034707292159L) != 9205357640488583168L;
    }

    public static final boolean i(long j) {
        return (j & 9223372034707292159L) == 9205357640488583168L;
    }

    public static final String j(com.quizlet.ui.models.content.listitem.o oVar) {
        return "rec:" + oVar.b().b() + ":" + oVar.d() + ":" + oVar.a();
    }

    public static final void k(androidx.compose.foundation.lazy.g gVar, InterfaceC4318y0 state, androidx.compose.foundation.lazy.A lazyListState, Function1 onFolderEvent) {
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(lazyListState, "lazyListState");
        Intrinsics.checkNotNullParameter(onFolderEvent, "onFolderEvent");
        if (state instanceof C4314w0) {
            C4314w0 c4314w0 = (C4314w0) state;
            androidx.compose.foundation.lazy.g.p(gVar, c4314w0.a, new androidx.compose.runtime.internal.d(true, -1493282782, new com.quizlet.baseui.base.d(state, 2)), 2);
            androidx.navigation.compose.x xVar = new androidx.navigation.compose.x(11);
            kotlinx.collections.immutable.b bVar = c4314w0.b;
            gVar.q(bVar.size(), new androidx.compose.ui.viewinterop.b(13, xVar, bVar), new com.quizlet.features.folders.addtofolder.composables.g(bVar, 2), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.features.folders.composables.V(bVar, onFolderEvent, lazyListState, 0)));
        }
    }
}
