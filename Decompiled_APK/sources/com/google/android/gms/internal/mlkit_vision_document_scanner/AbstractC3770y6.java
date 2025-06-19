package com.google.android.gms.internal.mlkit_vision_document_scanner;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.y6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3770y6 {
    public static final /* synthetic */ int a = 0;

    public static final io.reactivex.rxjava3.internal.operators.single.g a(io.reactivex.rxjava3.core.p pVar) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = pVar.g(com.quizlet.data.ext.a.b);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    public static final io.reactivex.rxjava3.internal.operators.maybe.h b(io.reactivex.rxjava3.core.p pVar) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        com.quizlet.data.ext.a aVar = com.quizlet.data.ext.a.c;
        pVar.getClass();
        io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, pVar, aVar);
        Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
        return hVar;
    }

    public static final io.reactivex.rxjava3.internal.operators.single.g c(Function1 function1, Object obj) {
        Intrinsics.checkNotNullParameter(function1, "<this>");
        return a((io.reactivex.rxjava3.core.p) function1.invoke(kotlin.collections.A.b(obj)));
    }
}
