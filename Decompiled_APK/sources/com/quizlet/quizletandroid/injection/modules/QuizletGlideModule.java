package com.quizlet.quizletandroid.injection.modules;

import android.content.Context;
import com.bumptech.glide.Glide;
import com.bumptech.glide.h;
import com.bumptech.glide.integration.okhttp3.b;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_common.C;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.images.loading.offline.c;
import java.io.InputStream;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletGlideModule extends C {
    public c a;
    public A b;

    @Override // com.google.android.gms.internal.mlkit_vision_common.C
    public final void b(Context context, Glide glide, h registry) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(glide, "glide");
        Intrinsics.checkNotNullParameter(registry, "registry");
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.a = (c) uVar.q0.get();
        this.b = (A) uVar.N.get();
        c cVar = this.a;
        if (cVar == null) {
            Intrinsics.m("persistentImageStore");
            throw null;
        }
        registry.c(com.quizlet.quizletandroid.ui.common.images.loading.offline.a.class, InputStream.class, new b(cVar));
        A a = this.b;
        if (a != null) {
            registry.j(new b(a));
        } else {
            Intrinsics.m("okHttpClient");
            throw null;
        }
    }
}
