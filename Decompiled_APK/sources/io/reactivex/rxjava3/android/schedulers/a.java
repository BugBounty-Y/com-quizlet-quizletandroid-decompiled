package io.reactivex.rxjava3.android.schedulers;

import android.os.Handler;
import android.os.Looper;
import io.reactivex.rxjava3.core.o;

/* loaded from: classes3.dex */
public abstract class a {
    public static final e a;

    static {
        Looper mainLooper = Looper.getMainLooper();
        o oVar = b.a;
        a = new e(new Handler(mainLooper), 0);
    }
}
