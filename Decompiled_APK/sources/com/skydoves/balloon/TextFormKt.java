package com.skydoves.balloon;

import android.content.Context;
import com.skydoves.balloon.TextForm;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class TextFormKt {
    @TextFormDsl
    public static final /* synthetic */ TextForm textForm(Context context, Function1<? super TextForm.Builder, Unit> block) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        TextForm.Builder builder = new TextForm.Builder(context);
        block.invoke(builder);
        return builder.build();
    }
}
