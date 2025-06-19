package com.quizlet.qatex;

import android.webkit.JavascriptInterface;
import androidx.work.impl.model.v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class a {
    public final /* synthetic */ b a;

    public a(b bVar) {
        this.a = bVar;
    }

    @JavascriptInterface
    public final void onError() {
        Function0 function0;
        v vVar = this.a.f;
        if (vVar == null || (function0 = (Function0) vVar.b) == null) {
            return;
        }
        function0.invoke();
    }

    @JavascriptInterface
    public final void onTextHeightMeasured(int i) {
        Function1 function1;
        v vVar = this.a.f;
        if (vVar == null || (function1 = (Function1) vVar.c) == null) {
            return;
        }
        function1.invoke(Integer.valueOf(i));
    }
}
