package com.braze.support;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class e implements Function0 {
    public final /* synthetic */ String a;

    public e(String str) {
        this.a = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return "Failed to create valid enum from string: " + this.a;
    }
}
