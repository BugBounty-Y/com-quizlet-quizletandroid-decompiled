package io.reactivex.rxjava3.disposables;

import androidx.compose.runtime.changelist.K;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.ArrayList;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class a implements b, c {
    public K a;
    public volatile boolean b;

    public static void e(K k) {
        if (k == null) {
            return;
        }
        ArrayList arrayList = null;
        for (Object obj : (Object[]) k.e) {
            if (obj instanceof b) {
                try {
                    ((b) obj).dispose();
                } catch (Throwable th) {
                    x7.b(th);
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(th);
                }
            }
        }
        if (arrayList != null) {
            if (arrayList.size() != 1) {
                throw new CompositeException(arrayList);
            }
            throw io.reactivex.rxjava3.internal.util.c.d((Throwable) arrayList.get(0));
        }
    }

    @Override // io.reactivex.rxjava3.disposables.c
    public final boolean a(b bVar) {
        if (!c(bVar)) {
            return false;
        }
        bVar.dispose();
        return true;
    }

    @Override // io.reactivex.rxjava3.disposables.c
    public final boolean b(b bVar) {
        Objects.requireNonNull(bVar, "disposable is null");
        if (!this.b) {
            synchronized (this) {
                try {
                    if (!this.b) {
                        K k = this.a;
                        if (k == null) {
                            k = new K(16);
                            this.a = k;
                        }
                        k.b(bVar);
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
    public final boolean c(b bVar) {
        Object obj;
        Objects.requireNonNull(bVar, "disposable is null");
        if (this.b) {
            return false;
        }
        synchronized (this) {
            try {
                if (this.b) {
                    return false;
                }
                K k = this.a;
                if (k != null) {
                    Object[] objArr = (Object[]) k.e;
                    int i = k.b;
                    int iHashCode = bVar.hashCode() * (-1640531527);
                    int i2 = (iHashCode ^ (iHashCode >>> 16)) & i;
                    Object obj2 = objArr[i2];
                    if (obj2 != null) {
                        if (obj2.equals(bVar)) {
                            k.h(i2, i, objArr);
                        } else {
                            do {
                                i2 = (i2 + 1) & i;
                                obj = objArr[i2];
                                if (obj == null) {
                                }
                            } while (!obj.equals(bVar));
                            k.h(i2, i, objArr);
                        }
                        return true;
                    }
                }
                return false;
            } finally {
            }
        }
    }

    public final void d() {
        if (this.b) {
            return;
        }
        synchronized (this) {
            try {
                if (this.b) {
                    return;
                }
                K k = this.a;
                this.a = null;
                e(k);
            } catch (Throwable th) {
                throw th;
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
                K k = this.a;
                this.a = null;
                e(k);
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
