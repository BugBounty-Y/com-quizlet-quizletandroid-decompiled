package androidx.camera.core.impl.utils.futures;

import androidx.appcompat.app.J;
import androidx.appcompat.widget.V;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class l implements com.google.common.util.concurrent.e {
    public ArrayList a;
    public ArrayList b;
    public final boolean c;
    public final AtomicInteger d;
    public final androidx.concurrent.futures.l e = Y5.b(new com.google.firebase.platforminfo.c(this));
    public androidx.concurrent.futures.i f;

    public l(ArrayList arrayList, boolean z, androidx.camera.core.impl.utils.executor.a aVar) {
        this.a = arrayList;
        this.b = new ArrayList(arrayList.size());
        this.c = z;
        this.d = new AtomicInteger(arrayList.size());
        a(new J(this, 6), T.a());
        if (this.a.isEmpty()) {
            this.f.b(new ArrayList(this.b));
            return;
        }
        for (int i = 0; i < this.a.size(); i++) {
            this.b.add(null);
        }
        ArrayList arrayList2 = this.a;
        for (int i2 = 0; i2 < arrayList2.size(); i2++) {
            com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) arrayList2.get(i2);
            eVar.a(new V(this, i2, eVar, 2), aVar);
        }
    }

    @Override // com.google.common.util.concurrent.e
    public final void a(Runnable runnable, Executor executor) {
        this.e.b.a(runnable, executor);
    }

    @Override // java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        ArrayList arrayList = this.a;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((com.google.common.util.concurrent.e) it2.next()).cancel(z);
            }
        }
        return this.e.cancel(z);
    }

    @Override // java.util.concurrent.Future
    public final Object get(long j, TimeUnit timeUnit) {
        return (List) this.e.b.get(j, timeUnit);
    }

    @Override // java.util.concurrent.Future
    public final boolean isCancelled() {
        return this.e.isCancelled();
    }

    @Override // java.util.concurrent.Future
    public final boolean isDone() {
        return this.e.b.isDone();
    }

    @Override // java.util.concurrent.Future
    public final Object get() throws InterruptedException {
        ArrayList arrayList = this.a;
        if (arrayList != null && !isDone()) {
            Iterator it2 = arrayList.iterator();
            loop0: while (it2.hasNext()) {
                com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) it2.next();
                while (!eVar.isDone()) {
                    try {
                        eVar.get();
                    } catch (Error e) {
                        throw e;
                    } catch (InterruptedException e2) {
                        throw e2;
                    } catch (Throwable unused) {
                        if (this.c) {
                            break loop0;
                        }
                    }
                }
            }
        }
        return (List) this.e.b.get();
    }
}
