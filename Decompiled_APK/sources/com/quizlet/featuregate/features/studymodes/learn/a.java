package com.quizlet.featuregate.features.studymodes.learn;

import androidx.work.impl.model.c;
import com.quizlet.generated.enums.C1;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public g a(c userProps) {
        switch (this.a) {
            case 2:
                Intrinsics.checkNotNullParameter(userProps, "userProps");
                g gVarE = userProps.t().e(b);
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return gVarE;
            default:
                Intrinsics.checkNotNullParameter(userProps, "userProps");
                g gVarE2 = userProps.q().e(c);
                Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
                return gVarE2;
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Boolean isEnabled = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isEnabled, "isEnabled");
                return isEnabled.booleanValue() ? p.f(C1.STANDARD) : p.f(C1.SIMPLIFIED_SEQUENCING);
            default:
                Boolean isFreeUser = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isFreeUser, "isFreeUser");
                return isFreeUser.booleanValue() ? p.f(b.a) : p.f(b.b);
        }
    }
}
