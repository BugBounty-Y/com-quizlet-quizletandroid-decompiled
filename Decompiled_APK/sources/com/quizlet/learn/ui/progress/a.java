package com.quizlet.learn.ui.progress;

import androidx.compose.runtime.W0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ W0 b;

    public /* synthetic */ a(W0 w0, int i) {
        this.a = i;
        this.b = w0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
        }
        return Float.valueOf(((Number) this.b.getValue()).floatValue());
    }
}
