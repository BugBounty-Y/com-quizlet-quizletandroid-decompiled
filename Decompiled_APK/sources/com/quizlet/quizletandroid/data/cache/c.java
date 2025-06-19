package com.quizlet.quizletandroid.data.cache;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends a {
    @Override // com.quizlet.quizletandroid.data.cache.a
    public final File b(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        File file = new File(this.a, String.valueOf(key.hashCode()));
        Intrinsics.checkNotNullExpressionValue(file, "get(...)");
        file.setLastModified(System.currentTimeMillis());
        return file;
    }

    @Override // com.quizlet.quizletandroid.data.cache.a
    public final void c(File file, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(file, "file");
    }
}
