package com.quizlet.search.composables;

import androidx.compose.foundation.lazy.grid.C0427b;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.search.composables.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4791j implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        androidx.compose.foundation.lazy.grid.v itemsIndexed = (androidx.compose.foundation.lazy.grid.v) obj;
        ((Integer) obj2).intValue();
        com.quizlet.ui.models.search.a item = (com.quizlet.ui.models.search.a) obj3;
        Intrinsics.checkNotNullParameter(itemsIndexed, "$this$itemsIndexed");
        Intrinsics.checkNotNullParameter(item, "item");
        return new C0427b(item instanceof com.quizlet.search.data.b ? AbstractC3173j0.d(this.a) : AbstractC3173j0.d(1));
    }
}
