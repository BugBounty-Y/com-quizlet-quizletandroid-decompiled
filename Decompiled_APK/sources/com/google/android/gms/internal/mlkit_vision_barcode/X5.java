package com.google.android.gms.internal.mlkit_vision_barcode;

import com.quizlet.data.model.ExerciseDetails;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class X5 {
    public static final /* synthetic */ int a = 0;

    public static final com.quizlet.ui.models.content.listitem.q f(ExerciseDetails exerciseDetails) {
        Intrinsics.checkNotNullParameter(exerciseDetails, "<this>");
        com.quizlet.ui.models.content.listitem.p pVarC = W5.c(exerciseDetails.j);
        return new com.quizlet.ui.models.content.listitem.q(exerciseDetails.b, exerciseDetails.c, exerciseDetails.d, exerciseDetails.g, exerciseDetails.f, exerciseDetails.h, exerciseDetails.e, exerciseDetails.i, pVarC);
    }

    public static final com.quizlet.ui.models.content.listitem.q g(com.quizlet.data.model.E0 e0) {
        Intrinsics.checkNotNullParameter(e0, "<this>");
        return new com.quizlet.ui.models.content.listitem.q(e0.b, e0.c, e0.d, "", e0.e, "", e0.f, e0.h, new com.quizlet.ui.models.content.listitem.p(e0.j, e0.k, "", ""));
    }

    public abstract boolean a(androidx.concurrent.futures.h hVar, androidx.concurrent.futures.d dVar, androidx.concurrent.futures.d dVar2);

    public abstract boolean b(androidx.concurrent.futures.h hVar, Object obj, Object obj2);

    public abstract boolean c(androidx.concurrent.futures.h hVar, androidx.concurrent.futures.g gVar, androidx.concurrent.futures.g gVar2);

    public abstract void d(androidx.concurrent.futures.g gVar, androidx.concurrent.futures.g gVar2);

    public abstract void e(androidx.concurrent.futures.g gVar, Thread thread);
}
