package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3771z {
    public static String a(View view) {
        if (!view.isAttachedToWindow()) {
            return "notAttached";
        }
        int visibility = view.getVisibility();
        if (visibility == 8) {
            return "viewGone";
        }
        if (visibility == 4) {
            return "viewInvisible";
        }
        if (visibility != 0) {
            return "viewNotVisible";
        }
        if (view.getAlpha() == DefinitionKt.NO_Float_VALUE) {
            return "viewAlphaZero";
        }
        return null;
    }

    public static io.reactivex.rxjava3.internal.operators.single.g b(com.quizlet.local.ormlite.util.c cVar, io.reactivex.rxjava3.internal.operators.flowable.b locals) {
        Intrinsics.checkNotNullParameter(locals, "locals");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = locals.g(new com.google.firebase.crashlytics.internal.common.j(cVar, 24));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    public static ArrayList c(com.quizlet.local.ormlite.util.c cVar, List locals) {
        Intrinsics.checkNotNullParameter(locals, "locals");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(locals, 10));
        Iterator it2 = locals.iterator();
        while (it2.hasNext()) {
            arrayList.add(cVar.h(it2.next()));
        }
        return arrayList;
    }
}
