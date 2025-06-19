package com.quizlet.quizletandroid.ui.common.images.loading.glide;

import com.bumptech.glide.load.h;
import com.bumptech.glide.load.model.q;
import com.bumptech.glide.load.model.r;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements r {
    public final r a;
    public final r b;
    public final com.quizlet.quizletandroid.ui.common.images.loading.offline.c c;

    public c(r stringLoader, r fileLoader, com.quizlet.quizletandroid.ui.common.images.loading.offline.c persistentImageResourceStore) {
        Intrinsics.checkNotNullParameter(stringLoader, "stringLoader");
        Intrinsics.checkNotNullParameter(fileLoader, "fileLoader");
        Intrinsics.checkNotNullParameter(persistentImageResourceStore, "persistentImageResourceStore");
        this.a = stringLoader;
        this.b = fileLoader;
        this.c = persistentImageResourceStore;
    }

    @Override // com.bumptech.glide.load.model.r
    public final boolean a(Object obj) {
        com.quizlet.quizletandroid.ui.common.images.loading.offline.a model = (com.quizlet.quizletandroid.ui.common.images.loading.offline.a) obj;
        Intrinsics.checkNotNullParameter(model, "model");
        return true;
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, h options) {
        com.quizlet.quizletandroid.ui.common.images.loading.offline.a model = (com.quizlet.quizletandroid.ui.common.images.loading.offline.a) obj;
        Intrinsics.checkNotNullParameter(model, "model");
        Intrinsics.checkNotNullParameter(options, "options");
        String url = model.a;
        com.quizlet.quizletandroid.ui.common.images.loading.offline.c cVar = this.c;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        File fileB = cVar.b.b(url);
        Intrinsics.checkNotNullExpressionValue(fileB, "get(...)");
        if (fileB.exists()) {
            return this.b.b(fileB, i, i2, options);
        }
        return model.b == com.quizlet.qutils.data.offline.c.a ? new q(new com.bumptech.glide.signature.b(fileB), new f(model, cVar)) : this.a.b(model.a, i, i2, options);
    }
}
