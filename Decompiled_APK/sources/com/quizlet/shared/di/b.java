package com.quizlet.shared.di;

import com.google.android.gms.ads.internal.client.C1608n;
import com.quizlet.eventlogger.KmpEventLogger;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class b extends r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1608n b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(C1608n c1608n, int i) {
        super(2);
        this.a = i;
        this.b = c1608n;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.remote.kmp.a platformHttpClient = new com.quizlet.remote.kmp.a((A) this.b.c);
                Intrinsics.checkNotNullParameter(platformHttpClient, "platformHttpClient");
                return platformHttpClient;
            case 1:
                org.koin.core.scope.a single2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single2, "$this$single");
                Intrinsics.checkNotNullParameter(it3, "it");
                return (com.quizlet.local.sqldelight.a) this.b.b;
            default:
                org.koin.core.scope.a single3 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it4 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single3, "$this$single");
                Intrinsics.checkNotNullParameter(it4, "it");
                KmpEventLogger platformEventLogger = (KmpEventLogger) this.b.d;
                Intrinsics.checkNotNullParameter(platformEventLogger, "platformEventLogger");
                return platformEventLogger;
        }
    }
}
