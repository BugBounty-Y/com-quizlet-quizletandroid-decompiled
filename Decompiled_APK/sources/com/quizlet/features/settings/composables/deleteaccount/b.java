package com.quizlet.features.settings.composables.deleteaccount;

import android.content.Context;
import androidx.activity.result.ActivityResult;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.quizlet.features.settings.composables.x;
import com.quizlet.features.settings.viewmodels.o;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;
    public final /* synthetic */ o c;

    public /* synthetic */ b(Context context, o oVar, int i) {
        this.a = i;
        this.b = context;
        this.c = oVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ActivityResult it2 = (ActivityResult) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                AbstractC3465h3.e(it2, this.b, new x(1, this.c, o.class, "onVerifyFacebookToken", "onVerifyFacebookToken(Ljava/lang/String;)V", 0, 6));
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                AbstractC3465h3.e(it2, this.b, new x(1, this.c, o.class, "onVerifyFacebookToken", "onVerifyFacebookToken(Ljava/lang/String;)V", 0, 8));
                break;
        }
        return Unit.a;
    }
}
