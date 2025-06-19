package com.quizlet.explanations.solution.solutionwall.limitedcontent;

import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0995g b;
    public final /* synthetic */ Function0 c;

    public /* synthetic */ a(C0995g c0995g, Function0 function0, int i) {
        this.a = i;
        this.b = c0995g;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = this.a;
        int iIntValue = ((Integer) obj).intValue();
        switch (i) {
            case 0:
                if (((C0985e) CollectionsKt.firstOrNull(this.b.c(iIntValue, iIntValue, "helpCenter"))) != null) {
                    this.c.invoke();
                }
                break;
            default:
                if (((C0985e) CollectionsKt.firstOrNull(this.b.c(iIntValue, iIntValue, "login"))) != null) {
                    this.c.invoke();
                }
                break;
        }
        return Unit.a;
    }
}
