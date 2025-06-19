package com.bumptech.glide.load.engine;

import android.content.Context;
import java.io.File;

/* loaded from: classes.dex */
public final class k implements com.bumptech.glide.util.g {
    public volatile Object a;
    public final Object b;

    public /* synthetic */ k(Object obj) {
        this.b = obj;
    }

    public com.bumptech.glide.load.engine.cache.a a() {
        if (((com.bumptech.glide.load.engine.cache.a) this.a) == null) {
            synchronized (this) {
                try {
                    if (((com.bumptech.glide.load.engine.cache.a) this.a) == null) {
                        File cacheDir = ((Context) ((com.bumptech.glide.load.engine.cache.c) this.b).a.b).getCacheDir();
                        androidx.work.impl.background.greedy.d dVar = null;
                        File file = cacheDir == null ? null : new File(cacheDir, "image_manager_disk_cache");
                        if (file != null && (file.isDirectory() || file.mkdirs())) {
                            dVar = new androidx.work.impl.background.greedy.d();
                            dVar.d = new com.quizlet.data.repository.explanations.myexplanations.a(7);
                            dVar.c = file;
                            dVar.a = 262144000L;
                            dVar.b = new com.quizlet.data.repository.qclass.c();
                        }
                        this.a = dVar;
                    }
                    if (((com.bumptech.glide.load.engine.cache.a) this.a) == null) {
                        this.a = new com.google.mlkit.common.sdkinternal.model.a(6);
                    }
                } finally {
                }
            }
        }
        return (com.bumptech.glide.load.engine.cache.a) this.a;
    }

    @Override // com.bumptech.glide.util.g
    public Object get() {
        if (this.a == null) {
            synchronized (this) {
                try {
                    if (this.a == null) {
                        Object obj = ((com.bumptech.glide.util.g) this.b).get();
                        com.bumptech.glide.util.f.c(obj, "Argument must not be null");
                        this.a = obj;
                    }
                } finally {
                }
            }
        }
        return this.a;
    }

    public k(int i) {
        this.b = new Object[i];
    }
}
