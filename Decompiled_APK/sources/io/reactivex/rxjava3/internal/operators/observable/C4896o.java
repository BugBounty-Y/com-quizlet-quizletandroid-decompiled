package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4896o extends io.reactivex.rxjava3.core.i {
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;
    public final int d;

    public /* synthetic */ C4896o(io.reactivex.rxjava3.core.k[] kVarArr, io.reactivex.rxjava3.functions.h hVar, int i, int i2) {
        this.a = i2;
        this.b = kVarArr;
        this.c = hVar;
        this.d = i;
    }

    public void A(i0 i0Var) {
        synchronized (this) {
            try {
                if (i0Var.b == 0 && i0Var == ((i0) this.c)) {
                    this.c = null;
                    io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) i0Var.get();
                    io.reactivex.rxjava3.internal.disposables.a.a(i0Var);
                    if (bVar == null) {
                        i0Var.d = true;
                    } else {
                        ((io.reactivex.rxjava3.internal.operators.mixed.b) this.b).z();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        i0 i0Var;
        boolean z;
        e0 e0Var;
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.core.k[] kVarArr = (io.reactivex.rxjava3.core.k[]) this.b;
                int length = kVarArr.length;
                if (length == 0) {
                    io.reactivex.rxjava3.internal.disposables.b.a(lVar);
                    return;
                }
                C4895n c4895n = new C4895n(lVar, (io.reactivex.rxjava3.functions.h) this.c, length, this.d);
                C4894m[] c4894mArr = c4895n.c;
                int length2 = c4894mArr.length;
                c4895n.a.a(c4895n);
                for (int i = 0; i < length2 && !c4895n.g && !c4895n.f; i++) {
                    kVarArr[i].c(c4894mArr[i]);
                }
                return;
            case 1:
                io.reactivex.rxjava3.core.k[] kVarArr2 = (io.reactivex.rxjava3.core.k[]) this.b;
                int length3 = kVarArr2.length;
                if (length3 == 0) {
                    io.reactivex.rxjava3.internal.disposables.b.a(lVar);
                    return;
                }
                x0 x0Var = new x0(lVar, (io.reactivex.rxjava3.functions.h) this.c, length3);
                int i2 = this.d;
                y0[] y0VarArr = x0Var.c;
                int length4 = y0VarArr.length;
                for (int i3 = 0; i3 < length4; i3++) {
                    y0VarArr[i3] = new y0(x0Var, i2);
                }
                x0Var.lazySet(0);
                x0Var.a.a(x0Var);
                for (int i4 = 0; i4 < length4 && !x0Var.e; i4++) {
                    kVarArr2[i4].c(y0VarArr[i4]);
                }
                return;
            default:
                synchronized (this) {
                    try {
                        i0Var = (i0) this.c;
                        if (i0Var == null) {
                            i0Var = new i0(this);
                            this.c = i0Var;
                        }
                        long j = i0Var.b + 1;
                        i0Var.b = j;
                        if (i0Var.c || j != this.d) {
                            z = false;
                        } else {
                            i0Var.c = true;
                            z = true;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                ((io.reactivex.rxjava3.internal.operators.mixed.b) this.b).c(new j0(lVar, this, i0Var));
                if (z) {
                    io.reactivex.rxjava3.internal.operators.mixed.b bVar = (io.reactivex.rxjava3.internal.operators.mixed.b) this.b;
                    while (true) {
                        AtomicReference atomicReference = (AtomicReference) bVar.b;
                        e0Var = (e0) atomicReference.get();
                        if (e0Var == null || e0Var.c()) {
                            e0 e0Var2 = new e0(atomicReference);
                            while (!atomicReference.compareAndSet(e0Var, e0Var2)) {
                                if (atomicReference.get() != e0Var) {
                                    break;
                                }
                            }
                            e0Var = e0Var2;
                        }
                    }
                    AtomicBoolean atomicBoolean = e0Var.a;
                    boolean z2 = !atomicBoolean.get() && atomicBoolean.compareAndSet(false, true);
                    try {
                        i0Var.accept(e0Var);
                        if (z2) {
                            ((io.reactivex.rxjava3.core.i) bVar.c).c(e0Var);
                            return;
                        }
                        return;
                    } catch (Throwable th2) {
                        x7.b(th2);
                        throw io.reactivex.rxjava3.internal.util.c.d(th2);
                    }
                }
                return;
        }
    }

    public void z(i0 i0Var) {
        synchronized (this) {
            try {
                if (((i0) this.c) == i0Var) {
                    i0Var.getClass();
                    long j = i0Var.b - 1;
                    i0Var.b = j;
                    if (j == 0) {
                        this.c = null;
                        ((io.reactivex.rxjava3.internal.operators.mixed.b) this.b).z();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public C4896o(io.reactivex.rxjava3.internal.operators.mixed.b bVar) {
        this.a = 2;
        TimeUnit timeUnit = TimeUnit.NANOSECONDS;
        this.b = bVar;
        this.d = 1;
    }
}
