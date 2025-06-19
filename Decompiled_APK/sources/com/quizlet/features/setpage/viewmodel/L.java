package com.quizlet.features.setpage.viewmodel;

import android.util.Log;
import androidx.glance.appwidget.protobuf.Z;
import com.android.billingclient.api.C1472a;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.play.core.review.ReviewException;
import java.util.HashMap;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        com.google.android.gms.tasks.m mVarH;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        P p = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            com.google.android.play.core.review.d dVar = p.C.b.a;
            Object[] objArr = {dVar.b};
            C1472a c1472a = com.google.android.play.core.review.d.c;
            c1472a.a("requestInAppReview (%s)", objArr);
            com.google.android.play.core.review.internal.j jVar = dVar.a;
            if (jVar == null) {
                Object[] objArr2 = new Object[0];
                if (Log.isLoggable("PlayCore", 6)) {
                    Log.e("PlayCore", C1472a.c(c1472a.b, "Play Store app is either not installed or not the official version", objArr2));
                }
                Locale locale = Locale.getDefault();
                HashMap map = com.google.android.play.core.review.model.a.a;
                mVarH = S3.h(new ReviewException(new Status(-1, String.format(locale, "Review Error(%d): %s", -1, !map.containsKey(-1) ? "" : androidx.compose.ui.node.B.i((String) map.get(-1), " (https://developer.android.com/reference/com/google/android/play/core/review/model/ReviewErrorCode.html#", (String) com.google.android.play.core.review.model.a.b.get(-1), ")")), null, null)));
            } else {
                com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
                jVar.a().post(new com.google.android.play.core.review.internal.g(jVar, fVar, fVar, new com.google.android.play.core.review.internal.i(dVar, fVar, fVar)));
                mVarH = fVar.a;
            }
            Intrinsics.checkNotNullExpressionValue(mVarH, "requestReviewFlow(...)");
            C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(this));
            c5028l.r();
            mVarH.addOnCompleteListener(new com.google.firebase.crashlytics.internal.common.j(c5028l, 19));
            obj = c5028l.q();
            if (obj == aVar) {
                Intrinsics.checkNotNullParameter(this, "frame");
            }
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        p.i1.j(new com.quizlet.features.infra.basestudy.data.models.m((com.quizlet.inapp.model.a) obj));
        return Unit.a;
    }
}
