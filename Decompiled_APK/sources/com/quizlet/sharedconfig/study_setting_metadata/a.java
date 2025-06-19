package com.quizlet.sharedconfig.study_setting_metadata;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class a implements Function1 {
    public final /* synthetic */ int a;

    public a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return Boolean.valueOf((((b) obj).a & this.a) != 0);
    }
}
