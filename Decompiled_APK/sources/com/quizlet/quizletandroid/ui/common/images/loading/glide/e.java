package com.quizlet.quizletandroid.ui.common.images.loading.glide;

import java.io.FileInputStream;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.bumptech.glide.load.data.d b;

    public /* synthetic */ e(com.bumptech.glide.load.data.d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                FileInputStream inStream = (FileInputStream) obj;
                Intrinsics.checkNotNullParameter(inStream, "inStream");
                this.b.i(inStream);
                break;
            default:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                this.b.a(new Exception(error));
                break;
        }
    }
}
