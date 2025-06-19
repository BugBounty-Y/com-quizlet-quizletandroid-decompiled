package com.quizlet.quizletandroid.ui.common.images.loading.offline;

import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import io.reactivex.rxjava3.internal.operators.maybe.f;
import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements i, h {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public static final b d = new b(2);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 1:
                File file = (File) obj;
                Intrinsics.checkNotNullParameter(file, "file");
                if (!file.exists()) {
                    break;
                } else {
                    break;
                }
            default:
                File it2 = (File) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (!it2.exists()) {
                    break;
                } else {
                    break;
                }
        }
        return f.a;
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        Intrinsics.checkNotNullParameter((Throwable) obj, "<unused var>");
        return true;
    }
}
