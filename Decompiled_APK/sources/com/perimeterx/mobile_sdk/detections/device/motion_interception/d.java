package com.perimeterx.mobile_sdk.detections.device.motion_interception;

import android.hardware.SensorEvent;
import android.view.MotionEvent;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L4;
import com.perimeterx.mobile_sdk.session.l;
import java.net.URL;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.C;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ int j;
    public final /* synthetic */ Object k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(Object obj, h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.k = obj;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        switch (this.j) {
            case 0:
                return new d((SensorEvent) this.k, hVar, 0);
            case 1:
                return new d((MotionEvent) this.k, hVar, 1);
            default:
                return new d((C) this.k, hVar, 2);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        h hVar = (h) obj2;
        switch (this.j) {
            case 0:
                return new d((SensorEvent) this.k, hVar, 0).invokeSuspend(Unit.a);
            case 1:
                return new d((MotionEvent) this.k, hVar, 1).invokeSuspend(Unit.a);
            default:
                return new d((C) this.k, hVar, 2).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = this.k;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                kotlinx.coroutines.channels.h hVar = g.j;
                if (hVar != null && !hVar.z()) {
                    hVar.o((SensorEvent) obj2);
                }
                break;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                kotlinx.coroutines.channels.h hVar2 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.g;
                if (hVar2 != null && !hVar2.z()) {
                    MotionEvent motionEvent = (MotionEvent) obj2;
                    Intrinsics.d(motionEvent);
                    hVar2.o(motionEvent);
                }
                break;
            default:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                if (L4.b != null) {
                    URL url = ((C) obj2).a.k();
                    Intrinsics.checkNotNullParameter(url, "url");
                    com.perimeterx.mobile_sdk.session.d dVarB = l.b(url, com.perimeterx.mobile_sdk.business_logic.b.a);
                    if (dVarB != null) {
                        Intrinsics.checkNotNullParameter(url, "url");
                        String string = url.toString();
                        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                        dVarB.p(string);
                    }
                }
                break;
        }
        return Unit.a;
    }
}
