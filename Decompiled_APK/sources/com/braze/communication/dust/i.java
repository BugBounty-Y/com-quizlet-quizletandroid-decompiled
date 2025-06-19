package com.braze.communication.dust;

import com.braze.managers.C1488a;
import com.braze.support.BrazeImageUtils;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Exception b;

    public /* synthetic */ i(int i, Exception exc) {
        this.a = i;
        this.b = exc;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return c.a(this.b);
            case 1:
                return C1488a.a(this.b);
            default:
                return BrazeImageUtils.getLocalBitmap$lambda$15(this.b);
        }
    }
}
