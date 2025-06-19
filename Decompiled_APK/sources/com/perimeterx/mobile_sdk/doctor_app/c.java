package com.perimeterx.mobile_sdk.doctor_app;

import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.constraintlayout.core.widgets.analyzer.f b;

    public /* synthetic */ c(androidx.constraintlayout.core.widgets.analyzer.f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.l(new com.braze.ui.inappmessage.listeners.a(25));
                break;
            case 1:
                this.b.l(null);
                break;
            case 2:
                com.perimeterx.mobile_sdk.doctor_app.model.a aVar = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.b());
                e action = e.b;
                Intrinsics.checkNotNullParameter(action, "action");
                this.b.d(B.f(aVar, new com.perimeterx.mobile_sdk.doctor_app.model.a(action)));
                break;
            case 3:
                com.perimeterx.mobile_sdk.doctor_app.model.a aVar2 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.g());
                e action2 = e.b;
                Intrinsics.checkNotNullParameter(action2, "action");
                this.b.d(B.f(aVar2, new com.perimeterx.mobile_sdk.doctor_app.model.a(action2)));
                break;
            case 4:
                com.perimeterx.mobile_sdk.doctor_app.model.a aVar3 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.b());
                e action3 = e.b;
                Intrinsics.checkNotNullParameter(action3, "action");
                this.b.d(B.f(aVar3, new com.perimeterx.mobile_sdk.doctor_app.model.a(action3)));
                break;
            case 5:
                androidx.constraintlayout.core.widgets.analyzer.f fVar = this.b;
                ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).d = true;
                com.perimeterx.mobile_sdk.doctor_app.model.c cVar = (com.perimeterx.mobile_sdk.doctor_app.model.c) fVar.h;
                cVar.d = true;
                com.perimeterx.mobile_sdk.doctor_app.state.d dVarA = cVar.a();
                if ((dVarA instanceof com.perimeterx.mobile_sdk.doctor_app.state.f ? (com.perimeterx.mobile_sdk.doctor_app.state.f) dVarA : null) != null) {
                    com.perimeterx.mobile_sdk.doctor_app.model.a action4 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new retrofit2.adapter.rxjava3.d(22));
                    Intrinsics.checkNotNullParameter(action4, "action");
                    fVar.d(B.f(action4));
                    break;
                }
                break;
            default:
                com.perimeterx.mobile_sdk.doctor_app.model.a aVar4 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.g());
                e action5 = e.b;
                Intrinsics.checkNotNullParameter(action5, "action");
                this.b.d(B.f(aVar4, new com.perimeterx.mobile_sdk.doctor_app.model.a(action5)));
                break;
        }
    }
}
