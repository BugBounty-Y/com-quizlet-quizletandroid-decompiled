package io.reactivex.rxjava3.internal.subscriptions;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.exceptions.ProtocolViolationException;
import java.util.concurrent.atomic.AtomicReference;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class c implements org.reactivestreams.b {
    public static final c a;
    public static final /* synthetic */ c[] b;

    static {
        c cVar = new c("CANCELLED", 0);
        a = cVar;
        b = new c[]{cVar};
    }

    public static boolean a(AtomicReference atomicReference) {
        org.reactivestreams.b bVar;
        org.reactivestreams.b bVar2 = (org.reactivestreams.b) atomicReference.get();
        c cVar = a;
        if (bVar2 == cVar || (bVar = (org.reactivestreams.b) atomicReference.getAndSet(cVar)) == cVar) {
            return false;
        }
        if (bVar == null) {
            return true;
        }
        bVar.cancel();
        return true;
    }

    public static boolean b(AtomicReference atomicReference, org.reactivestreams.b bVar) {
        while (!atomicReference.compareAndSet(null, bVar)) {
            if (atomicReference.get() != null) {
                bVar.cancel();
                if (atomicReference.get() == a) {
                    return false;
                }
                C7.c(new ProtocolViolationException("Subscription already set!"));
                return false;
            }
        }
        return true;
    }

    public static boolean c(long j) {
        if (j > 0) {
            return true;
        }
        C7.c(new IllegalArgumentException(d0.n(j, "n > 0 required but it was ")));
        return false;
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) b.clone();
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
    }
}
