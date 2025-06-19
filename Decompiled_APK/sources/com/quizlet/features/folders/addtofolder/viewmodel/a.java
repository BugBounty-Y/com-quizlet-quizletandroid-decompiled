package com.quizlet.features.folders.addtofolder.viewmodel;

import androidx.navigation.U;
import java.util.function.Predicate;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Predicate {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ a(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // java.util.function.Predicate
    public final boolean test(Object obj) {
        switch (this.a) {
            case 0:
                return ((Boolean) ((U) this.b).invoke(obj)).booleanValue();
            default:
                return ((Boolean) ((com.quizlet.features.universaluploadflow.flashcards.d) this.b).invoke(obj)).booleanValue();
        }
    }
}
