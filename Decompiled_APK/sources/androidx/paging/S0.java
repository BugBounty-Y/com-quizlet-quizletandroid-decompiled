package androidx.paging;

import android.os.Build;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class S0 {
    public final com.bumptech.glide.manager.p a = new com.bumptech.glide.manager.p(4);

    public abstract Integer a(T0 t0);

    public final void b() {
        boolean z;
        com.bumptech.glide.manager.p pVar = this.a;
        if (pVar.a) {
            z = false;
        } else {
            ReentrantLock reentrantLock = (ReentrantLock) pVar.b;
            try {
                reentrantLock.lock();
                if (pVar.a) {
                    z = false;
                } else {
                    pVar.a = true;
                    ArrayList arrayList = (ArrayList) pVar.c;
                    List<Function0> listW0 = CollectionsKt.w0(arrayList);
                    arrayList.clear();
                    reentrantLock.unlock();
                    for (Function0 it2 : listW0) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                        it2.invoke();
                        Unit unit = Unit.a;
                    }
                    z = true;
                }
            } finally {
                reentrantLock.unlock();
            }
        }
        if (z) {
            if (Build.ID != null && Log.isLoggable("Paging", 3)) {
                String message = "Invalidated PagingSource " + this;
                Intrinsics.checkNotNullParameter(message, "message");
            }
        }
    }

    public abstract Object c(N0 n0, kotlin.coroutines.jvm.internal.c cVar);
}
