package com.quizlet.features.questionnaire.steps;

import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements y0 {
    public static final com.quizlet.shared.usecase.folderstudymaterials.a a = new com.quizlet.shared.usecase.folderstudymaterials.a(27);

    @Override // androidx.lifecycle.y0
    public final w0 b(Class modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        g gVar = (g) extras.a(a);
        if (gVar == null) {
            throw new IllegalArgumentException("Missing Params for Step ViewModel");
        }
        if (modelClass.isAssignableFrom(b.class)) {
            e eVar = gVar instanceof e ? (e) gVar : null;
            if (eVar != null) {
                return new b(eVar.a, eVar.b);
            }
            throw new IllegalArgumentException("Invalid params type for QuestionnaireIntroViewModel");
        }
        if (modelClass.isAssignableFrom(c.class)) {
            f fVar = gVar instanceof f ? (f) gVar : null;
            if (fVar != null) {
                return new c(fVar.a, fVar.b);
            }
            throw new IllegalArgumentException("Invalid params type for QuestionnaireSchoolCourseViewModel");
        }
        if (!modelClass.isAssignableFrom(a.class)) {
            throw new IllegalArgumentException("Unknown ViewModel class: ".concat(modelClass.getName()));
        }
        d dVar = gVar instanceof d ? (d) gVar : null;
        if (dVar != null) {
            return new a(dVar.a, dVar.b);
        }
        throw new IllegalArgumentException("Invalid params type for QuestionnaireExamsViewModel");
    }
}
