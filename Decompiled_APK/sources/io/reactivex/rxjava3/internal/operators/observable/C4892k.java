package io.reactivex.rxjava3.internal.operators.observable;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4892k extends AtomicInteger implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final C4893l b;
    public com.bumptech.glide.load.engine.k c;
    public int d;
    public long e;
    public volatile boolean f;

    public C4892k(io.reactivex.rxjava3.core.l lVar, C4893l c4893l) {
        this.a = lVar;
        this.b = c4893l;
        this.c = c4893l.e;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        C4892k[] c4892kArr;
        if (this.f) {
            return;
        }
        this.f = true;
        C4893l c4893l = this.b;
        while (true) {
            AtomicReference atomicReference = c4893l.c;
            C4892k[] c4892kArr2 = (C4892k[]) atomicReference.get();
            int length = c4892kArr2.length;
            if (length == 0) {
                return;
            }
            int i = 0;
            while (true) {
                if (i >= length) {
                    i = -1;
                    break;
                } else if (c4892kArr2[i] == this) {
                    break;
                } else {
                    i++;
                }
            }
            if (i < 0) {
                return;
            }
            if (length == 1) {
                c4892kArr = C4893l.j;
            } else {
                C4892k[] c4892kArr3 = new C4892k[length - 1];
                System.arraycopy(c4892kArr2, 0, c4892kArr3, 0, i);
                System.arraycopy(c4892kArr2, i + 1, c4892kArr3, i, (length - i) - 1);
                c4892kArr = c4892kArr3;
            }
            while (!atomicReference.compareAndSet(c4892kArr2, c4892kArr)) {
                if (atomicReference.get() != c4892kArr2) {
                    break;
                }
            }
            return;
        }
    }
}
