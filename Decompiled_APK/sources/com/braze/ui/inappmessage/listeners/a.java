package com.braze.ui.inappmessage.listeners;

import androidx.constraintlayout.core.widgets.analyzer.f;
import com.comscore.streaming.EventType;
import com.perimeterx.mobile_sdk.doctor_app.d;
import com.perimeterx.mobile_sdk.doctor_app.e;
import com.perimeterx.mobile_sdk.doctor_app.state.c;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.perimeterx.mobile_sdk.doctor_app.ui.i;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                break;
            case 5:
                break;
            case 6:
                break;
            case 7:
                break;
            case 8:
                break;
            case 9:
                break;
            case 10:
                break;
            case 11:
                break;
            case 12:
                break;
            case 13:
                break;
            case 14:
                break;
            case 15:
                break;
            case 16:
                break;
            case 17:
                break;
            case 18:
                break;
            case 19:
                break;
            case 20:
                break;
            case 21:
                break;
            case EventType.WINDOW_STATE /* 22 */:
                break;
            case EventType.AUDIO /* 23 */:
                break;
            case EventType.VIDEO /* 24 */:
                break;
            case EventType.SUBS /* 25 */:
                break;
            case EventType.CDN /* 26 */:
                d dVar = PXDoctorActivity.j;
                if (dVar != null) {
                    dVar.invoke();
                }
                PXDoctorActivity.j = null;
                break;
            case 27:
                d dVar2 = PXDoctorActivity.j;
                if (dVar2 != null) {
                    dVar2.invoke();
                }
                PXDoctorActivity.j = null;
                break;
            case 28:
                f fVar = f.j;
                Intrinsics.d(fVar);
                com.perimeterx.mobile_sdk.doctor_app.model.a action = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.folderstudymaterials.d(22));
                Intrinsics.checkNotNullParameter(action, "action");
                fVar.d(B.f(action));
                break;
            default:
                f fVar2 = f.j;
                Intrinsics.d(fVar2);
                e action2 = e.c;
                Intrinsics.checkNotNullParameter(action2, "action");
                com.perimeterx.mobile_sdk.doctor_app.model.a aVar = new com.perimeterx.mobile_sdk.doctor_app.model.a(action2);
                e action3 = e.f;
                Intrinsics.checkNotNullParameter(action3, "action");
                fVar2.d(B.f(aVar, new com.perimeterx.mobile_sdk.doctor_app.model.a(action3), new com.perimeterx.mobile_sdk.doctor_app.model.a(i.a), new com.perimeterx.mobile_sdk.doctor_app.model.a(new c())));
                break;
        }
        return Unit.a;
    }
}
