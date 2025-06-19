package com.perimeterx.mobile_sdk.api_data;

import androidx.navigation.C1265a;
import io.ktor.client.plugins.M;
import io.ktor.client.plugins.W;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;

/* loaded from: classes2.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ A b;

    public /* synthetic */ g(A a, int i) {
        this.a = i;
        this.b = a;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                io.ktor.client.d HttpClient = (io.ktor.client.d) obj;
                Intrinsics.checkNotNullParameter(HttpClient, "$this$HttpClient");
                HttpClient.a(M.c, new C1265a(27));
                HttpClient.a(W.c, new C1265a(28));
                g block = new g(this.b, 1);
                Intrinsics.checkNotNullParameter(block, "block");
                HttpClient.d = new com.quizlet.quizletandroid.ui.subject.f(HttpClient.d, false, block, 8);
                break;
            default:
                io.ktor.client.engine.okhttp.b engine = (io.ktor.client.engine.okhttp.b) obj;
                Intrinsics.checkNotNullParameter(engine, "$this$engine");
                engine.b = this.b;
                break;
        }
        return Unit.a;
    }
}
