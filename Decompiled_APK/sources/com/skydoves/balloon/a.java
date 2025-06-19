package com.skydoves.balloon;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Balloon b;

    public /* synthetic */ a(Balloon balloon, int i) {
        this.a = i;
        this.b = balloon;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Balloon.dismiss$lambda$44(this.b);
            case 1:
                return Balloon.autoDismissRunnable_delegate$lambda$1(this.b);
            default:
                return Balloon.balloonPersistence_delegate$lambda$2(this.b);
        }
    }
}
