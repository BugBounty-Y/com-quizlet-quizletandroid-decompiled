package com.quizlet.infra.legacysyncengine.datasources;

import android.os.Looper;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public final ConcurrentHashMap.KeySetView a = ConcurrentHashMap.newKeySet();

    public abstract void a(b bVar);

    public abstract List b();

    public void c() {
        List listB;
        ConcurrentHashMap.KeySetView keySetView = this.a;
        if (keySetView.isEmpty() || (listB = b()) == null) {
            return;
        }
        Iterator it2 = keySetView.iterator();
        while (it2.hasNext()) {
            a callback = new a((b) it2.next(), listB, 1);
            Intrinsics.checkNotNullParameter(callback, "callback");
            if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                callback.run();
            } else {
                Intrinsics.d(io.reactivex.rxjava3.android.schedulers.b.a().b(callback));
            }
        }
    }

    public abstract io.reactivex.rxjava3.core.i d();

    public boolean e(b bVar) {
        List listB;
        if (bVar == null) {
            return false;
        }
        boolean zAdd = this.a.add(bVar);
        if (zAdd && (listB = b()) != null) {
            a callback = new a(bVar, listB, 0);
            Intrinsics.checkNotNullParameter(callback, "callback");
            if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                callback.run();
                return zAdd;
            }
            Intrinsics.d(io.reactivex.rxjava3.android.schedulers.b.a().b(callback));
        }
        return zAdd;
    }
}
