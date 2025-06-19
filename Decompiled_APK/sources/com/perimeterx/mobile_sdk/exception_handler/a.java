package com.perimeterx.mobile_sdk.exception_handler;

import androidx.compose.material.ripple.r;
import androidx.glance.appwidget.protobuf.Z;
import com.perimeterx.mobile_sdk.api_data.d;
import com.perimeterx.mobile_sdk.local_data.w;
import com.perimeterx.mobile_sdk.local_data.x;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ String l;
    public final /* synthetic */ com.perimeterx.mobile_sdk.detections.device.a m;
    public final /* synthetic */ r n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(String str, String str2, com.perimeterx.mobile_sdk.detections.device.a aVar, r rVar, h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = str2;
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
        a aVar;
        x key;
        String appId;
        com.perimeterx.mobile_sdk.local_data.b bVar;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                d dVar = new d();
                String str = this.k;
                String str2 = this.l;
                com.perimeterx.mobile_sdk.detections.device.a aVar3 = this.m;
                r rVar = this.n;
                this.j = 1;
                aVar = this;
                try {
                    if (dVar.c(str, str2, true, aVar3, rVar, aVar) == aVar2) {
                        return aVar2;
                    }
                } catch (Exception unused) {
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                aVar = this;
            }
            key = x.e;
            appId = aVar.k;
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(appId, "appId");
            bVar = w.c;
        } catch (Exception unused2) {
        }
        if (bVar != null) {
            bVar.c("", key, appId);
            return Unit.a;
        }
        Intrinsics.m("storage");
        throw null;
    }
}
