package io.reactivex.rxjava3.internal.operators.mixed;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.k;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.observable.d0;
import io.reactivex.rxjava3.internal.operators.observable.e0;
import io.reactivex.rxjava3.internal.operators.observable.k0;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class b extends i {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ b(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(l lVar) {
        e0 e0Var;
        d0[] d0VarArr;
        d0[] d0VarArr2;
        switch (this.a) {
            case 0:
                a aVar = new a(lVar, (i) this.c, 0);
                lVar.a(aVar);
                ((io.reactivex.rxjava3.core.a) this.b).b(aVar);
                return;
            case 1:
                a aVar2 = new a(lVar, (h) this.c, 1);
                lVar.a(aVar2);
                ((p) this.b).j(aVar2);
                return;
            case 2:
                break;
            case 3:
                try {
                    Object objApply = ((h) this.c).apply(this.b);
                    Objects.requireNonNull(objApply, "The mapper returned a null ObservableSource");
                    k kVar = (k) objApply;
                    if (!(kVar instanceof j)) {
                        kVar.c(lVar);
                        return;
                    }
                    try {
                        Object obj = ((j) kVar).get();
                        if (obj == null) {
                            io.reactivex.rxjava3.internal.disposables.b.a(lVar);
                            return;
                        }
                        k0 k0Var = new k0(lVar, obj);
                        lVar.a(k0Var);
                        k0Var.run();
                        return;
                    } catch (Throwable th) {
                        x7.b(th);
                        io.reactivex.rxjava3.internal.disposables.b.d(th, lVar);
                        return;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    io.reactivex.rxjava3.internal.disposables.b.d(th2, lVar);
                    return;
                }
            default:
                ((g) this.b).j(new io.reactivex.rxjava3.internal.operators.single.h(lVar, (com.quizlet.quizletandroid.ui.usersettings.b) this.c));
                return;
        }
        while (true) {
            AtomicReference atomicReference = (AtomicReference) this.b;
            e0Var = (e0) atomicReference.get();
            if (e0Var == null) {
                e0 e0Var2 = new e0(atomicReference);
                while (!atomicReference.compareAndSet(e0Var, e0Var2)) {
                    if (atomicReference.get() != e0Var) {
                        break;
                    }
                }
                e0Var = e0Var2;
            }
        }
        d0 d0Var = new d0(lVar, e0Var);
        lVar.a(d0Var);
        do {
            d0VarArr = (d0[]) e0Var.get();
            if (d0VarArr == e0.f) {
                Throwable th3 = e0Var.d;
                if (th3 != null) {
                    lVar.onError(th3);
                    return;
                } else {
                    lVar.onComplete();
                    return;
                }
            }
            int length = d0VarArr.length;
            d0VarArr2 = new d0[length + 1];
            System.arraycopy(d0VarArr, 0, d0VarArr2, 0, length);
            d0VarArr2[length] = d0Var;
        } while (!e0Var.compareAndSet(d0VarArr, d0VarArr2));
        if (d0Var.get() == null) {
            e0Var.d(d0Var);
        }
    }

    public void z() {
        AtomicReference atomicReference = (AtomicReference) this.b;
        e0 e0Var = (e0) atomicReference.get();
        if (e0Var == null || !e0Var.c()) {
            return;
        }
        while (!atomicReference.compareAndSet(e0Var, null) && atomicReference.get() == e0Var) {
        }
    }

    public b(i iVar) {
        this.a = 2;
        this.c = iVar;
        this.b = new AtomicReference();
    }
}
