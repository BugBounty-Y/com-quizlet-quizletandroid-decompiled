package io.ktor.utils.io;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.j256.ormlite.stmt.query.SimpleComparison;
import io.reactivex.rxjava3.exceptions.CompositeException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.y0;
import org.jsoup.parser.C5094a;

/* loaded from: classes3.dex */
public final class A implements io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int a = 2;
    public Object b;
    public Object c;

    public /* synthetic */ A() {
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        ((io.reactivex.rxjava3.core.q) this.b).a(bVar);
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        Object objApply;
        io.reactivex.rxjava3.internal.operators.completable.m mVar = (io.reactivex.rxjava3.internal.operators.completable.m) this.c;
        io.reactivex.rxjava3.functions.h hVar = (io.reactivex.rxjava3.functions.h) mVar.d;
        io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.b;
        if (hVar != null) {
            try {
                objApply = hVar.apply(th);
            } catch (Throwable th2) {
                x7.b(th2);
                qVar.onError(new CompositeException(th, th2));
                return;
            }
        } else {
            objApply = (Boolean) mVar.b;
        }
        if (objApply != null) {
            qVar.onSuccess(objApply);
            return;
        }
        NullPointerException nullPointerException = new NullPointerException("Value supplied was null");
        nullPointerException.initCause(th);
        qVar.onError(nullPointerException);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((io.reactivex.rxjava3.core.q) this.b).onSuccess(obj);
    }

    public String toString() {
        switch (this.a) {
            case 2:
                return SimpleComparison.LESS_THAN_OPERATION + ((String) this.b) + ">: " + ((String) this.c);
            default:
                return super.toString();
        }
    }

    public A(C5094a c5094a, String str, Object[] objArr) {
        c5094a.getClass();
        this.b = c5094a.m();
        this.c = String.format(str, objArr);
    }

    public A(io.reactivex.rxjava3.internal.operators.completable.m mVar, io.reactivex.rxjava3.core.q qVar) {
        this.c = mVar;
        this.b = qVar;
    }

    public A(k channel, y0 job) {
        Intrinsics.checkNotNullParameter(channel, "channel");
        Intrinsics.checkNotNullParameter(job, "job");
        this.b = channel;
        this.c = job;
    }
}
