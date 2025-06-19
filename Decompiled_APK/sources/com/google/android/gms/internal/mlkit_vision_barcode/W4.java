package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class W4 {
    public static final /* synthetic */ int a = 0;

    public static final Set a(assistantMode.enums.k kVar) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        while (kVar != b(kVar)) {
            linkedHashSet.add(b(kVar));
            kVar = b(kVar);
        }
        return CollectionsKt.A0(linkedHashSet);
    }

    public static final assistantMode.enums.k b(assistantMode.enums.k kVar) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        return com.quizlet.shared.utils.a.a[kVar.ordinal()] == 4 ? assistantMode.enums.k.b : assistantMode.enums.k.f;
    }

    public static final assistantMode.enums.k c(assistantMode.enums.k kVar) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        int iOrdinal = kVar.ordinal();
        return (iOrdinal == 11 || iOrdinal == 12) ? assistantMode.enums.k.d : kVar;
    }

    public static final assistantMode.enums.k d(assistantMode.enums.k kVar, Set possibleQuestionTypes, boolean z) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        Intrinsics.checkNotNullParameter(possibleQuestionTypes, "possibleQuestionTypes");
        while (!possibleQuestionTypes.contains(kVar) && kVar != b(kVar)) {
            kVar = b(kVar);
        }
        if (z) {
            assistantMode.enums.k kVar2 = assistantMode.enums.k.d;
            if (kVar == kVar2) {
                assistantMode.enums.k kVar3 = assistantMode.enums.k.m;
                if (possibleQuestionTypes.contains(kVar3)) {
                    return kVar3;
                }
            }
            if (kVar == kVar2) {
                assistantMode.enums.k kVar4 = assistantMode.enums.k.n;
                if (possibleQuestionTypes.contains(kVar4)) {
                    return kVar4;
                }
            }
        }
        return kVar;
    }

    public static final void e(String str) {
        throw new IllegalArgumentException(str);
    }

    public static final void f(String str) {
        throw new IllegalStateException(str);
    }

    public static final void g(String str) {
        throw new IllegalStateException(str);
    }
}
