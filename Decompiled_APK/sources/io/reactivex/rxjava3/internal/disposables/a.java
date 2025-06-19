package io.reactivex.rxjava3.internal.disposables;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.exceptions.ProtocolViolationException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a implements io.reactivex.rxjava3.disposables.b {
    public static final a a;
    public static final /* synthetic */ a[] b;

    static {
        a aVar = new a("DISPOSED", 0);
        a = aVar;
        b = new a[]{aVar};
    }

    public static boolean a(AtomicReference atomicReference) {
        io.reactivex.rxjava3.disposables.b bVar;
        io.reactivex.rxjava3.disposables.b bVar2 = (io.reactivex.rxjava3.disposables.b) atomicReference.get();
        a aVar = a;
        if (bVar2 == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) atomicReference.getAndSet(aVar)) == aVar) {
            return false;
        }
        if (bVar == null) {
            return true;
        }
        bVar.dispose();
        return true;
    }

    public static boolean b(io.reactivex.rxjava3.disposables.b bVar) {
        return bVar == a;
    }

    public static boolean c(AtomicReference atomicReference, io.reactivex.rxjava3.disposables.b bVar) {
        while (true) {
            io.reactivex.rxjava3.disposables.b bVar2 = (io.reactivex.rxjava3.disposables.b) atomicReference.get();
            if (bVar2 == a) {
                if (bVar == null) {
                    return false;
                }
                bVar.dispose();
                return false;
            }
            while (!atomicReference.compareAndSet(bVar2, bVar)) {
                if (atomicReference.get() != bVar2) {
                    break;
                }
            }
            return true;
        }
    }

    public static boolean d(AtomicReference atomicReference, io.reactivex.rxjava3.disposables.b bVar) {
        while (true) {
            io.reactivex.rxjava3.disposables.b bVar2 = (io.reactivex.rxjava3.disposables.b) atomicReference.get();
            if (bVar2 == a) {
                if (bVar == null) {
                    return false;
                }
                bVar.dispose();
                return false;
            }
            while (!atomicReference.compareAndSet(bVar2, bVar)) {
                if (atomicReference.get() != bVar2) {
                    break;
                }
            }
            if (bVar2 == null) {
                return true;
            }
            bVar2.dispose();
            return true;
        }
    }

    public static boolean e(AtomicReference atomicReference, io.reactivex.rxjava3.disposables.b bVar) {
        Objects.requireNonNull(bVar, "d is null");
        while (!atomicReference.compareAndSet(null, bVar)) {
            if (atomicReference.get() != null) {
                bVar.dispose();
                if (atomicReference.get() == a) {
                    return false;
                }
                C7.c(new ProtocolViolationException("Disposable already set!"));
                return false;
            }
        }
        return true;
    }

    public static boolean f(io.reactivex.rxjava3.disposables.b bVar, io.reactivex.rxjava3.disposables.b bVar2) {
        if (bVar2 == null) {
            C7.c(new NullPointerException("next is null"));
            return false;
        }
        if (bVar == null) {
            return true;
        }
        bVar2.dispose();
        C7.c(new ProtocolViolationException("Disposable already set!"));
        return false;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) b.clone();
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
    }
}
