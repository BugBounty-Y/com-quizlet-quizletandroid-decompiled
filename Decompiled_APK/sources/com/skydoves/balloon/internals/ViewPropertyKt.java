package com.skydoves.balloon.internals;

import android.view.View;
import com.quizlet.features.infra.legacyadapter.viewholder.a;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ViewPropertyKt {
    public static final /* synthetic */ ViewPropertyDelegate viewProperty(View view, Object obj) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        return new ViewPropertyDelegate(obj, new a(view, 4));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit viewProperty$lambda$0(View view) {
        view.invalidate();
        return Unit.a;
    }
}
