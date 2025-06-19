package com.appsflyer.internal;

import com.appsflyer.internal.AFa1tSDK;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return ((AFa1tSDK.AFa1vSDK) this.b).getRevenue();
            default:
                return ((AFc1eSDK) this.b).m_();
        }
    }
}
