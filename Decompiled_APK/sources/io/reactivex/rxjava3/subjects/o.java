package io.reactivex.rxjava3.subjects;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class o extends AtomicReference implements l {
    public final ArrayList a = new ArrayList(16);
    public volatile boolean b;
    public volatile int c;

    @Override // io.reactivex.rxjava3.subjects.l
    public final void a(m mVar) {
        int iIntValue;
        int i;
        if (mVar.getAndIncrement() != 0) {
            return;
        }
        ArrayList arrayList = this.a;
        io.reactivex.rxjava3.core.l lVar = mVar.a;
        Integer num = (Integer) mVar.c;
        if (num != null) {
            iIntValue = num.intValue();
        } else {
            iIntValue = 0;
            mVar.c = 0;
        }
        int iAddAndGet = 1;
        while (!mVar.d) {
            int i2 = this.c;
            while (i2 != iIntValue) {
                if (mVar.d) {
                    mVar.c = null;
                    return;
                }
                Object obj = arrayList.get(iIntValue);
                if (this.b && (i = iIntValue + 1) == i2 && i == (i2 = this.c)) {
                    if (io.reactivex.rxjava3.internal.util.e.a(obj)) {
                        lVar.onComplete();
                    } else {
                        lVar.onError(((io.reactivex.rxjava3.internal.util.d) obj).a);
                    }
                    mVar.c = null;
                    mVar.d = true;
                    return;
                }
                lVar.b(obj);
                iIntValue++;
            }
            if (iIntValue == this.c) {
                mVar.c = Integer.valueOf(iIntValue);
                iAddAndGet = mVar.addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            }
        }
        mVar.c = null;
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final void add(Object obj) {
        this.a.add(obj);
        this.c++;
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final void b(Serializable serializable) {
        this.a.add(serializable);
        this.c++;
        this.b = true;
    }

    @Override // io.reactivex.rxjava3.subjects.l
    public final Object getValue() {
        int i = this.c;
        if (i == 0) {
            return null;
        }
        ArrayList arrayList = this.a;
        Object obj = arrayList.get(i - 1);
        if (!io.reactivex.rxjava3.internal.util.e.a(obj) && !(obj instanceof io.reactivex.rxjava3.internal.util.d)) {
            return obj;
        }
        if (i == 1) {
            return null;
        }
        return arrayList.get(i - 2);
    }
}
