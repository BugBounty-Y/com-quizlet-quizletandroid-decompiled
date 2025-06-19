package com.bumptech.glide.integration.okhttp3;

import com.bumptech.glide.load.model.C1535c;
import com.bumptech.glide.load.model.r;
import com.bumptech.glide.load.model.s;
import com.bumptech.glide.load.model.x;
import java.io.File;
import java.io.InputStream;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.InterfaceC5075d;

/* loaded from: classes.dex */
public final class b implements s {
    public static volatile A c;
    public final /* synthetic */ int a;
    public final Object b;

    public b(com.quizlet.quizletandroid.ui.common.images.loading.offline.c persistentImageResourceStore) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(persistentImageResourceStore, "persistentImageResourceStore");
        this.b = persistentImageResourceStore;
    }

    @Override // com.bumptech.glide.load.model.s
    public final r a(x multiFactory) {
        switch (this.a) {
            case 0:
                return new c((InterfaceC5075d) this.b, 0);
            case 1:
                return new c((C1535c) this.b, 2);
            case 2:
                return new com.bumptech.glide.load.model.stream.a((com.google.firebase.platforminfo.c) this.b);
            default:
                Intrinsics.checkNotNullParameter(multiFactory, "multiFactory");
                r rVarB = multiFactory.b(String.class, InputStream.class);
                Intrinsics.checkNotNullExpressionValue(rVarB, "build(...)");
                r rVarB2 = multiFactory.b(File.class, InputStream.class);
                Intrinsics.checkNotNullExpressionValue(rVarB2, "build(...)");
                return new com.quizlet.quizletandroid.ui.common.images.loading.glide.c(rVarB, rVarB2, (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) this.b);
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public b(int i) {
        this(c);
        this.a = i;
        switch (i) {
            case 1:
                this.b = new C1535c(3);
                return;
            case 2:
                this.b = new com.google.firebase.platforminfo.c(18);
                return;
            default:
                if (c == null) {
                    synchronized (b.class) {
                        try {
                            if (c == null) {
                                c = new A();
                            }
                        } finally {
                        }
                    }
                }
                return;
        }
    }

    public b(InterfaceC5075d interfaceC5075d) {
        this.a = 0;
        this.b = interfaceC5075d;
    }
}
