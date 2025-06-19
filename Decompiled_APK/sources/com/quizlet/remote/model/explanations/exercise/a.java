package com.quizlet.remote.model.explanations.exercise;

import androidx.work.impl.model.e;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.ExerciseDetails;
import com.quizlet.data.model.U;
import com.quizlet.data.model.X;
import com.quizlet.data.repository.course.membership.c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.exercise.ExerciseDetailsResponse;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ e a;
    public final /* synthetic */ String b;

    public a(e eVar, String str) {
        this.a = eVar;
        this.b = str;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Boolean bool;
        ExerciseDetailsResponse.Models models;
        List list;
        RemoteMeteringInfo remoteMeteringInfo;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        ExerciseDetailsResponse exerciseDetailsResponse = (ExerciseDetailsResponse) response.a();
        e eVar = this.a;
        ExerciseDetails exerciseDetails = null;
        X xB = (exerciseDetailsResponse == null || (remoteMeteringInfo = exerciseDetailsResponse.e) == null) ? null : com.quizlet.quizletandroid.logging.initializer.a.b(remoteMeteringInfo);
        ExerciseDetailsResponse exerciseDetailsResponse2 = (ExerciseDetailsResponse) response.a();
        if (exerciseDetailsResponse2 != null && (models = exerciseDetailsResponse2.d) != null && (list = models.a) != null) {
            exerciseDetails = (ExerciseDetails) CollectionsKt.firstOrNull(S.f((c) eVar.c, list));
        }
        ExerciseDetailsResponse exerciseDetailsResponse3 = (ExerciseDetailsResponse) response.a();
        return exerciseDetails != null ? p.f(new U(exerciseDetails, xB, (exerciseDetailsResponse3 == null || (bool = exerciseDetailsResponse3.f) == null) ? false : bool.booleanValue())) : p.d(new NoSuchElementException(this.b));
    }
}
