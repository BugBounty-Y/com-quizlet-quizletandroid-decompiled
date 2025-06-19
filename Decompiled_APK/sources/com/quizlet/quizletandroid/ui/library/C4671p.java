package com.quizlet.quizletandroid.ui.library;

import androidx.compose.foundation.lazy.grid.C0427b;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4671p implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.paging.compose.d b;
    public final /* synthetic */ int c;

    public /* synthetic */ C4671p(androidx.paging.compose.d dVar, int i, int i2) {
        this.a = i2;
        this.b = dVar;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        androidx.compose.foundation.lazy.grid.v impressionableItems = (androidx.compose.foundation.lazy.grid.v) obj;
        int iIntValue = ((Integer) obj2).intValue();
        switch (i) {
            case 0:
                Intrinsics.checkNotNullParameter(impressionableItems, "$this$impressionableItems");
                return new C0427b(((com.quizlet.library.data.d) this.b.b(iIntValue)) instanceof com.quizlet.library.data.c ? AbstractC3173j0.d(this.c) : AbstractC3173j0.d(1));
            case 1:
                Intrinsics.checkNotNullParameter(impressionableItems, "$this$items");
                return new C0427b(((com.quizlet.ui.models.search.a) this.b.b(iIntValue)) instanceof com.quizlet.ui.models.content.ads.a ? AbstractC3173j0.d(this.c) : AbstractC3173j0.d(1));
            case 2:
                Intrinsics.checkNotNullParameter(impressionableItems, "$this$items");
                return new C0427b(((com.quizlet.ui.models.search.a) this.b.b(iIntValue)) instanceof com.quizlet.ui.models.content.ads.a ? AbstractC3173j0.d(this.c) : AbstractC3173j0.d(1));
            case 3:
                Intrinsics.checkNotNullParameter(impressionableItems, "$this$items");
                return new C0427b(((com.quizlet.ui.models.search.a) this.b.b(iIntValue)) instanceof com.quizlet.ui.models.content.ads.a ? AbstractC3173j0.d(this.c) : AbstractC3173j0.d(1));
            case 4:
                Intrinsics.checkNotNullParameter(impressionableItems, "$this$items");
                return new C0427b(((com.quizlet.ui.models.search.a) this.b.b(iIntValue)) instanceof com.quizlet.ui.models.content.ads.a ? AbstractC3173j0.d(this.c) : AbstractC3173j0.d(1));
            default:
                Intrinsics.checkNotNullParameter(impressionableItems, "$this$items");
                return new C0427b(((com.quizlet.ui.models.search.a) this.b.b(iIntValue)) instanceof com.quizlet.ui.models.content.ads.a ? AbstractC3173j0.d(this.c) : AbstractC3173j0.d(1));
        }
    }
}
