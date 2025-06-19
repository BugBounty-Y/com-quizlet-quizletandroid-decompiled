package com.perimeterx.mobile_sdk.doctor_app;

import com.braze.triggers.managers.h;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ d(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke();
                break;
            case 1:
                this.b.invoke();
                break;
            default:
                this.b.invoke();
                break;
        }
        return Unit.a;
    }
}
