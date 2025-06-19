package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4904x extends io.reactivex.rxjava3.internal.observers.a {
    public final /* synthetic */ int f;
    public final Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4904x(io.reactivex.rxjava3.core.l lVar, Object obj, int i) {
        super(lVar);
        this.f = i;
        this.g = obj;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.f) {
            case 0:
                this.a.b(obj);
                if (this.e == 0) {
                    try {
                        ((io.reactivex.rxjava3.functions.d) this.g).accept(obj);
                        break;
                    } catch (Throwable th) {
                        x7.b(th);
                        this.b.dispose();
                        onError(th);
                        return;
                    }
                }
                break;
            case 1:
                int i = this.e;
                io.reactivex.rxjava3.core.l lVar = this.a;
                if (i != 0) {
                    lVar.b(null);
                    break;
                } else {
                    try {
                        if (((io.reactivex.rxjava3.functions.i) this.g).test(obj)) {
                            lVar.b(obj);
                            break;
                        }
                    } catch (Throwable th2) {
                        x7.b(th2);
                        this.b.dispose();
                        onError(th2);
                        return;
                    }
                }
                break;
            default:
                if (!this.d) {
                    int i2 = this.e;
                    io.reactivex.rxjava3.core.l lVar2 = this.a;
                    if (i2 != 0) {
                        lVar2.b(null);
                        break;
                    } else {
                        try {
                            Object objApply = ((io.reactivex.rxjava3.functions.h) this.g).apply(obj);
                            Objects.requireNonNull(objApply, "The mapper function returned a null value.");
                            lVar2.b(objApply);
                            break;
                        } catch (Throwable th3) {
                            x7.b(th3);
                            this.b.dispose();
                            onError(th3);
                        }
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        Object objPoll;
        switch (this.f) {
            case 0:
                Object objPoll2 = this.c.poll();
                if (objPoll2 != null) {
                    ((io.reactivex.rxjava3.functions.d) this.g).accept(objPoll2);
                }
                return objPoll2;
            case 1:
                break;
            default:
                Object objPoll3 = this.c.poll();
                if (objPoll3 == null) {
                    return null;
                }
                Object objApply = ((io.reactivex.rxjava3.functions.h) this.g).apply(objPoll3);
                Objects.requireNonNull(objApply, "The mapper function returned a null value.");
                return objApply;
        }
        do {
            objPoll = this.c.poll();
            if (objPoll != null) {
            }
            return objPoll;
        } while (!((io.reactivex.rxjava3.functions.i) this.g).test(objPoll));
        return objPoll;
    }
}
