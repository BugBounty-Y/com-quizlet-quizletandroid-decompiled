package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class x0 extends AtomicInteger implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.h b;
    public final y0[] c;
    public final Object[] d;
    public volatile boolean e;

    public x0(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar, int i) {
        this.a = lVar;
        this.b = hVar;
        this.c = new y0[i];
        this.d = new Object[i];
    }

    public final void a() {
        y0[] y0VarArr = this.c;
        for (y0 y0Var : y0VarArr) {
            y0Var.b.clear();
        }
        for (y0 y0Var2 : y0VarArr) {
            io.reactivex.rxjava3.internal.disposables.a.a(y0Var2.e);
        }
    }

    public final void b() {
        Throwable th;
        if (getAndIncrement() != 0) {
            return;
        }
        y0[] y0VarArr = this.c;
        io.reactivex.rxjava3.core.l lVar = this.a;
        Object[] objArr = this.d;
        int iAddAndGet = 1;
        while (true) {
            int i = 0;
            int i2 = 0;
            for (y0 y0Var : y0VarArr) {
                if (objArr[i2] == null) {
                    boolean z = y0Var.c;
                    Object objPoll = y0Var.b.poll();
                    boolean z2 = objPoll == null;
                    if (this.e) {
                        a();
                        return;
                    }
                    if (z) {
                        Throwable th2 = y0Var.d;
                        if (th2 != null) {
                            this.e = true;
                            a();
                            lVar.onError(th2);
                            return;
                        } else if (z2) {
                            this.e = true;
                            a();
                            lVar.onComplete();
                            return;
                        }
                    }
                    if (z2) {
                        i++;
                    } else {
                        objArr[i2] = objPoll;
                    }
                } else if (y0Var.c && (th = y0Var.d) != null) {
                    this.e = true;
                    a();
                    lVar.onError(th);
                    return;
                }
                i2++;
            }
            if (i != 0) {
                iAddAndGet = addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            } else {
                try {
                    Object objApply = this.b.apply(objArr.clone());
                    Objects.requireNonNull(objApply, "The zipper returned a null value");
                    lVar.b(objApply);
                    Arrays.fill(objArr, (Object) null);
                } catch (Throwable th3) {
                    x7.b(th3);
                    a();
                    lVar.onError(th3);
                    return;
                }
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.e) {
            return;
        }
        this.e = true;
        for (y0 y0Var : this.c) {
            io.reactivex.rxjava3.internal.disposables.a.a(y0Var.e);
        }
        if (getAndIncrement() == 0) {
            for (y0 y0Var2 : this.c) {
                y0Var2.b.clear();
            }
        }
    }
}
