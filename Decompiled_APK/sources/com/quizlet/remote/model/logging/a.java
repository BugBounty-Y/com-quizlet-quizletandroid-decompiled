package com.quizlet.remote.model.logging;

import io.reactivex.rxjava3.functions.d;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.J;
import timber.log.c;

/* loaded from: classes3.dex */
public final class a implements d {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                J it2 = (J) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                try {
                    it2.close();
                    break;
                } catch (Exception e) {
                    c.a.g(e.toString(), new Object[0]);
                    return;
                }
            default:
                Throwable it3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                c.a.g(it3.toString(), new Object[0]);
                break;
        }
    }
}
