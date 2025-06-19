package io.reactivex.rxjava3.internal.disposables;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.internal.schedulers.s;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.disposables.c {
    public LinkedList a;
    public volatile boolean b;

    @Override // io.reactivex.rxjava3.disposables.c
    public final boolean a(io.reactivex.rxjava3.disposables.b bVar) {
        if (!c(bVar)) {
            return false;
        }
        ((s) bVar).dispose();
        return true;
    }

    @Override // io.reactivex.rxjava3.disposables.c
    public final boolean b(io.reactivex.rxjava3.disposables.b bVar) {
        if (!this.b) {
            synchronized (this) {
                try {
                    if (!this.b) {
                        LinkedList linkedList = this.a;
                        if (linkedList == null) {
                            linkedList = new LinkedList();
                            this.a = linkedList;
                        }
                        linkedList.add(bVar);
                        return true;
                    }
                } finally {
                }
            }
        }
        bVar.dispose();
        return false;
    }

    @Override // io.reactivex.rxjava3.disposables.c
    public final boolean c(io.reactivex.rxjava3.disposables.b bVar) {
        if (this.b) {
            return false;
        }
        synchronized (this) {
            try {
                if (this.b) {
                    return false;
                }
                LinkedList linkedList = this.a;
                if (linkedList != null && linkedList.remove(bVar)) {
                    return true;
                }
                return false;
            } finally {
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.b) {
            return;
        }
        synchronized (this) {
            try {
                if (this.b) {
                    return;
                }
                this.b = true;
                LinkedList linkedList = this.a;
                ArrayList arrayList = null;
                this.a = null;
                if (linkedList == null) {
                    return;
                }
                Iterator it2 = linkedList.iterator();
                while (it2.hasNext()) {
                    try {
                        ((io.reactivex.rxjava3.disposables.b) it2.next()).dispose();
                    } catch (Throwable th) {
                        x7.b(th);
                        if (arrayList == null) {
                            arrayList = new ArrayList();
                        }
                        arrayList.add(th);
                    }
                }
                if (arrayList != null) {
                    if (arrayList.size() != 1) {
                        throw new CompositeException(arrayList);
                    }
                    throw io.reactivex.rxjava3.internal.util.c.d((Throwable) arrayList.get(0));
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }
}
