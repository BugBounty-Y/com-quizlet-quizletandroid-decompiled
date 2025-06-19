package com.google.android.gms.internal.mlkit_vision_document_scanner;

import assistantMode.refactored.types.AndroidWriteMasteryBuckets;
import assistantMode.refactored.types.FlashcardsMasteryBuckets;
import assistantMode.refactored.types.IosWriteMasteryBuckets;
import assistantMode.refactored.types.SpellMasteryBuckets;
import assistantMode.refactored.types.TotalProgress;
import assistantMode.refactored.types.WebWriteMasteryBuckets;
import com.quizlet.studiablemodels.StudiableTotalProgress;
import com.quizlet.studiablemodels.StudiableWriteMasteryBuckets;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class N6 {
    public static final /* synthetic */ int a = 0;

    public static final StudiableTotalProgress a(TotalProgress totalProgress) {
        Intrinsics.checkNotNullParameter(totalProgress, "<this>");
        assistantMode.refactored.types.c cVar = totalProgress.a;
        if (cVar instanceof AndroidWriteMasteryBuckets) {
            AndroidWriteMasteryBuckets androidWriteMasteryBuckets = (AndroidWriteMasteryBuckets) cVar;
            return new StudiableTotalProgress(new StudiableWriteMasteryBuckets(androidWriteMasteryBuckets.a, androidWriteMasteryBuckets.b), totalProgress.b);
        }
        if ((cVar instanceof SpellMasteryBuckets) || (cVar instanceof IosWriteMasteryBuckets) || (cVar instanceof FlashcardsMasteryBuckets) || (cVar instanceof WebWriteMasteryBuckets)) {
            throw new IllegalArgumentException("Unsupported MasteryBuckets type: ".concat(cVar.getClass().getSimpleName()));
        }
        throw new NoWhenBranchMatchedException();
    }
}
