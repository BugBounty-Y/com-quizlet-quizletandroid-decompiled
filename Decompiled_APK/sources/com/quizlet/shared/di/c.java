package com.quizlet.shared.di;

import com.google.android.gms.ads.internal.client.C1608n;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function2 {
    public final /* synthetic */ int a = 1;

    public /* synthetic */ c(int i) {
        super(i);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.featuregate.experimentmanager.a delegate = com.quizlet.featuregate.experimentmanager.a.a;
                Intrinsics.checkNotNullParameter(delegate, "platformRawExperimentManager");
                Intrinsics.checkNotNullParameter(delegate, "platformRawExperimentManager");
                Intrinsics.checkNotNullParameter(delegate, "delegate");
                return new com.quizlet.shared.experimentmanager.a();
            default:
                org.koin.core.scope.a single2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single2, "$this$single");
                Intrinsics.checkNotNullParameter(it3, "it");
                return "api.quizlet.com";
        }
    }

    public c(C1608n c1608n) {
        super(2);
    }
}
