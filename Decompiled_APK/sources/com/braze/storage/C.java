package com.braze.storage;

import com.braze.support.ReflectionUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final /* synthetic */ class C implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ J c;

    public /* synthetic */ C(String str, J j) {
        this.a = 1;
        this.b = str;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return f0.a(this.c, this.b);
            case 1:
                return ReflectionUtils.getDeclaredMethodQuietly$lambda$2(this.b, this.c);
            default:
                return com.braze.triggers.managers.a.a(this.c, this.b);
        }
    }

    public /* synthetic */ C(J j, String str, int i) {
        this.a = i;
        this.c = j;
        this.b = str;
    }
}
