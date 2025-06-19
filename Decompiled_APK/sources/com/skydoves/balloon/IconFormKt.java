package com.skydoves.balloon;

import android.content.Context;
import com.skydoves.balloon.IconForm;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class IconFormKt {
    @IconFormDsl
    public static final /* synthetic */ IconForm iconForm(Context context, Function1<? super IconForm.Builder, Unit> block) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        IconForm.Builder builder = new IconForm.Builder(context);
        block.invoke(builder);
        return builder.build();
    }
}
