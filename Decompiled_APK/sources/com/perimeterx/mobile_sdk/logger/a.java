package com.perimeterx.mobile_sdk.logger;

import androidx.compose.material.ripple.r;
import androidx.glance.appwidget.protobuf.Z;
import com.perimeterx.mobile_sdk.api_data.d;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ JSONObject l;
    public final /* synthetic */ com.perimeterx.mobile_sdk.detections.device.a m;
    public final /* synthetic */ r n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(String str, JSONObject jSONObject, com.perimeterx.mobile_sdk.detections.device.a aVar, r rVar, h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = jSONObject;
        this.m = aVar;
        this.n = rVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                d dVar = new d();
                String str = this.k;
                String string = this.l.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                com.perimeterx.mobile_sdk.detections.device.a aVar2 = this.m;
                r rVar = this.n;
                this.j = 1;
                if (dVar.c(str, string, false, aVar2, rVar, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
        } catch (Exception e) {
            String message = "failed to report failure. exception = " + e;
            b level = b.a;
            Intrinsics.checkNotNullParameter(message, "message");
            Intrinsics.checkNotNullParameter(level, "level");
        }
        return Unit.a;
    }
}
