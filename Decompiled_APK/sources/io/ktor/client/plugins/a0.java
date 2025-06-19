package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A0;

/* loaded from: classes3.dex */
public final class a0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Long k;
    public final /* synthetic */ io.ktor.client.request.c l;
    public final /* synthetic */ A0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a0(Long l, io.ktor.client.request.c cVar, A0 a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l;
        this.l = cVar;
        this.m = a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a0(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            long jLongValue = this.k.longValue();
            this.j = 1;
            if (kotlinx.coroutines.E.n(jLongValue, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        io.ktor.client.request.c request = this.l;
        Intrinsics.checkNotNullParameter(request, "request");
        io.ktor.http.w wVar = request.a;
        wVar.a();
        StringBuilder sb = new StringBuilder(256);
        AbstractC3108b7.b(wVar, sb);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        X key = X.a;
        Intrinsics.checkNotNullParameter(key, "key");
        Map map = (Map) request.f.d(io.ktor.client.engine.h.a);
        Y y = (Y) (map != null ? map.get(key) : null);
        HttpRequestTimeoutException httpRequestTimeoutException = new HttpRequestTimeoutException(string, y != null ? y.a : null, null);
        b0.a.n("Request timeout: " + request.a);
        String message = httpRequestTimeoutException.getMessage();
        Intrinsics.d(message);
        kotlinx.coroutines.E.j(this.m, message, httpRequestTimeoutException);
        return Unit.a;
    }
}
