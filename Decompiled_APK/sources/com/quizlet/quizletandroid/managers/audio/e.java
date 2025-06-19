package com.quizlet.quizletandroid.managers.audio;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ File b;

    public /* synthetic */ e(File file, int i) {
        this.a = i;
        this.b = file;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((Throwable) obj, "<unused var>");
                File file = this.b;
                if (file.exists()) {
                    file.delete();
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter((Throwable) obj, "<unused var>");
                File file2 = this.b;
                if (file2.exists()) {
                    file2.delete();
                    break;
                }
                break;
        }
    }
}
