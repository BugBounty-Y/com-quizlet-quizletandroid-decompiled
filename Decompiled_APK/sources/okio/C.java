package okio;

import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class C {
    public static final B a = new B(new byte[0], 0, 0, false, false);
    public static final int b;
    public static final AtomicReference[] c;

    static {
        int iHighestOneBit = Integer.highestOneBit((Runtime.getRuntime().availableProcessors() * 2) - 1);
        b = iHighestOneBit;
        AtomicReference[] atomicReferenceArr = new AtomicReference[iHighestOneBit];
        for (int i = 0; i < iHighestOneBit; i++) {
            atomicReferenceArr[i] = new AtomicReference();
        }
        c = atomicReferenceArr;
    }

    public static final void a(B segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        if (segment.f != null || segment.g != null) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (segment.d) {
            return;
        }
        AtomicReference atomicReference = c[(int) (Thread.currentThread().getId() & (b - 1))];
        B b2 = a;
        B b3 = (B) atomicReference.getAndSet(b2);
        if (b3 == b2) {
            return;
        }
        int i = b3 != null ? b3.c : 0;
        if (i >= 65536) {
            atomicReference.set(b3);
            return;
        }
        segment.f = b3;
        segment.b = 0;
        segment.c = i + 8192;
        atomicReference.set(segment);
    }

    public static final B b() {
        AtomicReference atomicReference = c[(int) (Thread.currentThread().getId() & (b - 1))];
        B b2 = a;
        B b3 = (B) atomicReference.getAndSet(b2);
        if (b3 == b2) {
            return new B();
        }
        if (b3 == null) {
            atomicReference.set(null);
            return new B();
        }
        atomicReference.set(b3.f);
        b3.f = null;
        b3.c = 0;
        return b3;
    }
}
