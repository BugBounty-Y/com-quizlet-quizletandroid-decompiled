package com.braze;

import android.graphics.BitmapFactory;
import com.braze.U;
import com.braze.enums.Month;
import com.braze.support.BrazeImageUtils;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.set.IrrelevantStudySetPostBody;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class U implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;

    public /* synthetic */ U(int i, Month month, int i2) {
        this.a = 0;
        this.b = i;
        this.d = month;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.setDateOfBirth$lambda$18(this.b, (Month) this.d, this.c);
            case 1:
                return com.braze.requests.util.b.a((com.braze.requests.util.b) this.d, this.b, this.c);
            case 2:
                return BrazeImageUtils.calculateInSampleSize$lambda$5((BitmapFactory.Options) this.d, this.b, this.c);
            case 3:
                final com.quizlet.data.repository.set.f fVar = (com.quizlet.data.repository.set.f) ((androidx.compose.foundation.text.input.internal.u) this.d).b;
                final int i = this.b;
                final int i2 = this.c;
                io.reactivex.rxjava3.internal.operators.single.g gVar = new io.reactivex.rxjava3.internal.operators.single.g(new io.reactivex.rxjava3.internal.operators.flowable.b(new io.reactivex.rxjava3.functions.j() { // from class: com.quizlet.data.repository.set.d
                    @Override // io.reactivex.rxjava3.functions.j
                    public final Object get() {
                        f fVar2 = fVar;
                        return AbstractC3738u6.b((com.quizlet.data.connectivity.a) fVar2.c, new U(fVar2, i, i2, 4), new r(17));
                    }
                }, 4), new com.google.android.material.floatingactionbutton.c(fVar, 15), 2);
                Intrinsics.checkNotNullExpressionValue(gVar, "onErrorResumeNext(...)");
                return gVar;
            default:
                com.quizlet.remote.model.set.a aVar = (com.quizlet.remote.model.set.a) ((com.quizlet.remote.model.set.d) ((com.google.firebase.messaging.p) ((com.quizlet.data.repository.set.f) this.d).b).b).a;
                io.reactivex.rxjava3.internal.operators.single.g gVarG = aVar.a.a(new ApiPostBody<>(kotlin.collections.A.b(new IrrelevantStudySetPostBody(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()), this.b, this.c, 1)))).g(new com.quizlet.remote.model.set.c());
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
        }
    }

    public /* synthetic */ U(Object obj, int i, int i2, int i3) {
        this.a = i3;
        this.d = obj;
        this.b = i;
        this.c = i2;
    }
}
