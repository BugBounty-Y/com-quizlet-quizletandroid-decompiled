package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class p extends AtomicInteger implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.q a;
    public final io.reactivex.rxjava3.functions.h b;
    public final q[] c;
    public Object[] d;

    public p(int i, io.reactivex.rxjava3.core.q qVar, io.reactivex.rxjava3.functions.h hVar) {
        super(i);
        this.a = qVar;
        this.b = hVar;
        q[] qVarArr = new q[i];
        for (int i2 = 0; i2 < i; i2++) {
            qVarArr[i2] = new q(this, i2);
        }
        this.c = qVarArr;
        this.d = new Object[i];
    }

    public final void a(int i, Throwable th) {
        if (getAndSet(0) <= 0) {
            C7.c(th);
            return;
        }
        q[] qVarArr = this.c;
        int length = qVarArr.length;
        for (int i2 = 0; i2 < i; i2++) {
            q qVar = qVarArr[i2];
            qVar.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(qVar);
        }
        while (true) {
            i++;
            if (i >= length) {
                this.d = null;
                this.a.onError(th);
                return;
            } else {
                q qVar2 = qVarArr[i];
                qVar2.getClass();
                io.reactivex.rxjava3.internal.disposables.a.a(qVar2);
            }
        }
    }

    public final boolean b() {
        return get() <= 0;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (getAndSet(0) > 0) {
            for (q qVar : this.c) {
                qVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.a(qVar);
            }
            this.d = null;
        }
    }
}
