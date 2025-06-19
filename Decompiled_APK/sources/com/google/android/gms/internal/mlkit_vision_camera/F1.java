package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Bundle;
import androidx.navigation.C1289k;
import androidx.navigation.C1291m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5038w;
import kotlinx.serialization.KSerializer;

/* loaded from: classes2.dex */
public abstract class F1 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(kotlinx.coroutines.channels.u r4, kotlin.jvm.functions.Function0 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof kotlinx.coroutines.channels.s
            if (r0 == 0) goto L13
            r0 = r6
            kotlinx.coroutines.channels.s r0 = (kotlinx.coroutines.channels.s) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.channels.s r0 = new kotlinx.coroutines.channels.s
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlin.jvm.functions.Function0 r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Throwable -> L29
            goto L6b
        L29:
            r4 = move-exception
            goto L71
        L2b:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.coroutines.CoroutineContext r6 = r0.getContext()
            kotlinx.coroutines.i0 r2 = kotlinx.coroutines.C5023i0.a
            kotlin.coroutines.CoroutineContext$Element r6 = r6.get(r2)
            if (r6 != r4) goto L75
            r0.j = r5     // Catch: java.lang.Throwable -> L29
            r0.l = r3     // Catch: java.lang.Throwable -> L29
            kotlinx.coroutines.l r6 = new kotlinx.coroutines.l     // Catch: java.lang.Throwable -> L29
            kotlin.coroutines.h r2 = kotlin.coroutines.intrinsics.h.b(r0)     // Catch: java.lang.Throwable -> L29
            r6.<init>(r3, r2)     // Catch: java.lang.Throwable -> L29
            r6.r()     // Catch: java.lang.Throwable -> L29
            com.quizlet.features.setpage.termlist.ads.c r2 = new com.quizlet.features.setpage.termlist.ads.c     // Catch: java.lang.Throwable -> L29
            r3 = 4
            r2.<init>(r6, r3)     // Catch: java.lang.Throwable -> L29
            kotlinx.coroutines.channels.t r4 = (kotlinx.coroutines.channels.t) r4     // Catch: java.lang.Throwable -> L29
            r4.n(r2)     // Catch: java.lang.Throwable -> L29
            java.lang.Object r4 = r6.q()     // Catch: java.lang.Throwable -> L29
            if (r4 != r1) goto L68
            java.lang.String r6 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r6)     // Catch: java.lang.Throwable -> L29
        L68:
            if (r4 != r1) goto L6b
            return r1
        L6b:
            r5.invoke()
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        L71:
            r5.invoke()
            throw r4
        L75:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "awaitClose() can only be invoked from the producer context"
            r4.<init>(r5)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.F1.a(kotlinx.coroutines.channels.u, kotlin.jvm.functions.Function0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static kotlinx.coroutines.channels.t b(kotlinx.coroutines.C c, Function2 function2) {
        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
        kotlinx.coroutines.channels.a aVar = kotlinx.coroutines.channels.a.a;
        kotlinx.coroutines.D d = kotlinx.coroutines.D.a;
        kotlinx.coroutines.channels.t tVar = new kotlinx.coroutines.channels.t(AbstractC5038w.b(c, nVar), D1.a(0, 4, aVar), true, true);
        tVar.m0(d, tVar, function2);
        return tVar;
    }

    public static final Object c(C1291m c1291m, C4950i route) {
        Intrinsics.checkNotNullParameter(c1291m, "<this>");
        Intrinsics.checkNotNullParameter(route, "route");
        Bundle bundle = c1291m.h.a();
        if (bundle == null) {
            kotlin.collections.V.c();
            bundle = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
            Intrinsics.checkNotNullParameter(bundle, "source");
        }
        Map mapH = c1291m.b.h();
        LinkedHashMap typeMap = new LinkedHashMap(kotlin.collections.U.a(mapH.size()));
        for (Map.Entry entry : mapH.entrySet()) {
            typeMap.put(entry.getKey(), ((C1289k) entry.getValue()).a);
        }
        KSerializer deserializer = P1.e(route);
        Intrinsics.checkNotNullParameter(deserializer, "<this>");
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        androidx.navigation.serialization.g gVar = new androidx.navigation.serialization.g(bundle, typeMap);
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return deserializer.deserialize(gVar);
    }
}
