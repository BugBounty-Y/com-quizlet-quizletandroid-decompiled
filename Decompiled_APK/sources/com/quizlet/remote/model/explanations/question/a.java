package com.quizlet.remote.model.explanations.question;

import androidx.work.impl.model.l;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.C4151n1;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.X;
import com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.question.QuestionResponse;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ l a;
    public final /* synthetic */ String b;

    public a(l lVar, String str) {
        this.a = lVar;
        this.b = str;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Boolean bool;
        RemoteMeteringInfo remoteMeteringInfo;
        QuestionResponse.Models models;
        List list;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        QuestionResponse questionResponse = (QuestionResponse) response.a();
        X xB = null;
        Question question = (questionResponse == null || (models = questionResponse.d) == null || (list = models.a) == null) ? null : (Question) CollectionsKt.firstOrNull(S.f((c) this.a.c, list));
        QuestionResponse questionResponse2 = (QuestionResponse) response.a();
        if (questionResponse2 != null && (remoteMeteringInfo = questionResponse2.e) != null) {
            xB = com.quizlet.quizletandroid.logging.initializer.a.b(remoteMeteringInfo);
        }
        QuestionResponse questionResponse3 = (QuestionResponse) response.a();
        return question != null ? p.f(new C4151n1(question, xB, (questionResponse3 == null || (bool = questionResponse3.f) == null) ? false : bool.booleanValue())) : p.d(new NoSuchElementException(this.b));
    }
}
