package com.bumptech.glide;

import android.content.Context;
import com.quizlet.quizletandroid.injection.modules.QuizletGlideModule;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class GeneratedAppGlideModuleImpl extends GeneratedAppGlideModule {
    public final QuizletGlideModule a;

    public GeneratedAppGlideModuleImpl(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = new QuizletGlideModule();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.C
    public final void a(Context context, d builder) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a.getClass();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.C
    public final void b(Context context, Glide glide, h registry) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(glide, "glide");
        Intrinsics.checkNotNullParameter(registry, "registry");
        registry.j(new com.bumptech.glide.integration.okhttp3.b(0));
        this.a.b(context, glide, registry);
    }
}
