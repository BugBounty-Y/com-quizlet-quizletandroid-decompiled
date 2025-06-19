package com.quizlet.features.practicetest.takingtest;

import androidx.compose.runtime.C0776c;
import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;

    public /* synthetic */ k(F f, int i) {
        this.a = i;
        this.b = f;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return C0776c.z(Boolean.valueOf(this.b.b()));
            default:
                return Boolean.valueOf(this.b.i > 1);
        }
    }
}
