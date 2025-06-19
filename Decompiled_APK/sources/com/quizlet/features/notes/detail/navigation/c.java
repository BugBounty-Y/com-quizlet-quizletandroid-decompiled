package com.quizlet.features.notes.detail.navigation;

import androidx.navigation.B;
import androidx.navigation.L;
import com.quizlet.features.flashcards.C4237k;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ B b;

    public /* synthetic */ c(int i, B b) {
        this.a = i;
        this.b = b;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        L navOptions = (L) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.a(this.b.b.c, new C4237k(24));
                break;
            case 1:
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.a(this.b.b.c, new C4237k(23));
                break;
            case 2:
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.a(this.b.b.c, new com.quizlet.features.practicetest.navigation.a(1));
                break;
            case 3:
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.a(this.b.b.c, new com.quizlet.features.universaluploadflow.flashcards.d(3));
                break;
            default:
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.a(this.b.b.c, new com.quizlet.features.universaluploadflow.flashcards.d(2));
                break;
        }
        return Unit.a;
    }
}
