package com.quizlet.braze;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class f extends c {
    public final int b;
    public final b c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.b = 4;
        this.c = b.a;
    }

    @Override // com.quizlet.braze.c
    public final b a() {
        return this.c;
    }

    @Override // com.quizlet.braze.c
    public final int b() {
        return this.b;
    }
}
