package com.quizlet.remote.model.practicetests;

import androidx.compose.foundation.text.input.internal.u;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import com.quizlet.data.exceptions.practicetests.PracticeTestPrivateException;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.data.model.P0;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.r;
import java.util.UUID;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import retrofit2.HttpException;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C3 k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(C3 c3, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c3;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Exception {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C3 c3 = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                c3.a();
                r rVar = (r) c3.a;
                String str = this.l;
                String string = UUID.randomUUID().toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                String strB = ((C4636c) c3.i).b();
                this.j = 1;
                obj = rVar.b(str, string, strB, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            RemoteQuestionBankPreviewResponse remoteQuestionBankPreviewResponse = (RemoteQuestionBankPreviewResponse) ((ApiThreeWrapper) obj).a();
            if (remoteQuestionBankPreviewResponse != null) {
                return (P0) ((u) c3.d).a(remoteQuestionBankPreviewResponse);
            }
            throw new PracticeTestsException("Practice Test Detail should not be null");
        } catch (Exception e) {
            if (!(e instanceof HttpException)) {
                throw e;
            }
            HttpException httpException = (HttpException) e;
            if (httpException.a == 403) {
                throw new PracticeTestPrivateException();
            }
            throw new PracticeTestsException(httpException.b);
        }
    }
}
