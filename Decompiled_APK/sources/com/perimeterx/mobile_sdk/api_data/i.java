package com.perimeterx.mobile_sdk.api_data;

import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;
import okhttp3.A;
import okhttp3.C5078g;
import okhttp3.C5079h;
import okhttp3.z;

/* loaded from: classes2.dex */
public abstract class i {
    public static final io.ktor.client.c a;

    static {
        int i = 0;
        z zVar = new z();
        ArrayList arrayList = new ArrayList();
        String str = com.perimeterx.mobile_sdk.configurations.i.a;
        String[] pins = {"sha256/V5L96iSCz0XLFgvKi7YVo6M4SIkOP9zSkDjZ0EoU6b8="};
        Intrinsics.checkNotNullParameter("*.perimeterx.net", "pattern");
        Intrinsics.checkNotNullParameter(pins, "pins");
        arrayList.add(new C5078g(pins[0]));
        C5079h certificatePinner = new C5079h(CollectionsKt.A0(arrayList), null);
        Intrinsics.checkNotNullParameter(certificatePinner, "certificatePinner");
        if (!certificatePinner.equals(zVar.t)) {
            zVar.z = null;
        }
        zVar.t = certificatePinner;
        A a2 = new A(zVar);
        io.ktor.client.engine.okhttp.a engineFactory = io.ktor.client.engine.okhttp.a.a;
        g block = new g(a2, i);
        Intrinsics.checkNotNullParameter(engineFactory, "engineFactory");
        Intrinsics.checkNotNullParameter(block, "block");
        io.ktor.client.d dVar = new io.ktor.client.d();
        block.invoke(dVar);
        Function1 block2 = dVar.d;
        Intrinsics.checkNotNullParameter(block2, "block");
        io.ktor.client.engine.okhttp.b bVar = new io.ktor.client.engine.okhttp.b();
        bVar.a = new com.sdk.growthbook.utils.a(4);
        bVar.c = 10;
        block2.invoke(bVar);
        io.ktor.client.engine.okhttp.f fVar = new io.ktor.client.engine.okhttp.f(bVar);
        io.ktor.client.c cVar = new io.ktor.client.c(fVar, dVar);
        CoroutineContext.Element element = cVar.d.get(C5023i0.a);
        Intrinsics.d(element);
        ((InterfaceC5025j0) element).Q(new com.quizlet.ui.compose.modifiers.b(fVar, 3));
        a = cVar;
    }
}
