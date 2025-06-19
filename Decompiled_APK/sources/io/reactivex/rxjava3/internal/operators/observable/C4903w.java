package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4903w extends io.reactivex.rxjava3.internal.observers.a {
    public Object f;
    public boolean g;

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.d) {
            return;
        }
        int i = this.e;
        io.reactivex.rxjava3.core.l lVar = this.a;
        if (i != 0) {
            lVar.b(obj);
            return;
        }
        try {
            if (this.g) {
                boolean zEquals = Objects.equals(this.f, obj);
                this.f = obj;
                if (zEquals) {
                    return;
                }
            } else {
                this.g = true;
                this.f = obj;
            }
            lVar.b(obj);
        } catch (Throwable th) {
            x7.b(th);
            this.b.dispose();
            onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        while (true) {
            Object objPoll = this.c.poll();
            if (objPoll == null) {
                return null;
            }
            if (!this.g) {
                this.g = true;
                this.f = objPoll;
                return objPoll;
            }
            if (!Objects.equals(this.f, objPoll)) {
                this.f = objPoll;
                return objPoll;
            }
            this.f = objPoll;
        }
    }
}
