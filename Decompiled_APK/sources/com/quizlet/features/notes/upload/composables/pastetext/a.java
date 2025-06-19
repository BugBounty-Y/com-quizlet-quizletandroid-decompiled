package com.quizlet.features.notes.upload.composables.pastetext;

import androidx.compose.runtime.H0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ H0 c;

    public /* synthetic */ a(Function1 function1, H0 h0, int i) {
        this.a = i;
        this.b = function1;
        this.c = h0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                String it2 = (String) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(it2);
                this.c.j(it2.length());
                break;
            default:
                Integer num = (Integer) obj;
                this.c.j(num.intValue());
                this.b.invoke(num);
                break;
        }
        return Unit.a;
    }
}
