package com.perimeterx.mobile_sdk.doctor_app.ui;

import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class p implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ p(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar);
                com.perimeterx.mobile_sdk.doctor_app.e action = com.perimeterx.mobile_sdk.doctor_app.e.c;
                Intrinsics.checkNotNullParameter(action, "action");
                com.perimeterx.mobile_sdk.doctor_app.model.a aVar = new com.perimeterx.mobile_sdk.doctor_app.model.a(action);
                com.perimeterx.mobile_sdk.doctor_app.e action2 = com.perimeterx.mobile_sdk.doctor_app.e.g;
                Intrinsics.checkNotNullParameter(action2, "action");
                fVar.d(B.f(aVar, new com.perimeterx.mobile_sdk.doctor_app.model.a(action2), new com.perimeterx.mobile_sdk.doctor_app.model.a(i.b), new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.h())));
                break;
        }
        return Unit.a;
    }
}
