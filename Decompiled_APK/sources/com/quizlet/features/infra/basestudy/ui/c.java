package com.quizlet.features.infra.basestudy.ui;

import androidx.compose.ui.text.AbstractC1013n;
import com.quizlet.features.universaluploadflow.data.s;
import com.quizlet.features.universaluploadflow.data.t;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ c(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    public final void a(AbstractC1013n it2) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(com.quizlet.ui.models.webpage.c.c);
                break;
            case 1:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(s.a);
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(t.a);
                break;
        }
    }
}
