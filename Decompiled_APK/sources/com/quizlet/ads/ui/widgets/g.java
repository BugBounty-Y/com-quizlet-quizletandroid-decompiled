package com.quizlet.ads.ui.widgets;

import android.os.CountDownTimer;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final class g extends CountDownTimer {
    public final /* synthetic */ Function1 a;
    public final /* synthetic */ Function0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(long j, Function1 function1, Function0 function0) {
        super(j, 1000L);
        this.a = function1;
        this.b = function0;
    }

    @Override // android.os.CountDownTimer
    public final void onFinish() {
        this.b.invoke();
    }

    @Override // android.os.CountDownTimer
    public final void onTick(long j) {
        this.a.invoke(Long.valueOf(j));
    }
}
