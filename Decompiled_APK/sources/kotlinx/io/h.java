package kotlinx.io;

import java.util.concurrent.atomic.AtomicReferenceArray;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public abstract class h {
    public static final g a;
    public static final int b;
    public static final int c;
    public static final int d;
    public static final int e;
    public static final AtomicReferenceArray f;
    public static final AtomicReferenceArray g;

    static {
        int iIntValue;
        int i = 0;
        byte[] data = new byte[0];
        Intrinsics.checkNotNullParameter(data, "data");
        a = new g(data, 0, 0, null);
        int iHighestOneBit = Integer.highestOneBit((Runtime.getRuntime().availableProcessors() * 2) - 1);
        b = iHighestOneBit;
        int i2 = iHighestOneBit / 2;
        int i3 = i2 >= 1 ? i2 : 1;
        c = i3;
        String property = System.getProperty("kotlinx.io.pool.size.bytes", Intrinsics.b(System.getProperty("java.vm.name"), "Dalvik") ? "0" : "4194304");
        Intrinsics.checkNotNullExpressionValue(property, "getProperty(...)");
        Integer intOrNull = StringsKt.toIntOrNull(property);
        if (intOrNull != null && (iIntValue = intOrNull.intValue()) >= 0) {
            i = iIntValue;
        }
        d = i;
        int i4 = i / i3;
        if (i4 < 8192) {
            i4 = 8192;
        }
        e = i4;
        f = new AtomicReferenceArray(iHighestOneBit);
        g = new AtomicReferenceArray(i3);
    }

    public static final void a(g segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        if (segment.f != null || segment.g != null) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        j jVar = segment.d;
        if (jVar != null && jVar.g()) {
            return;
        }
        AtomicReferenceArray atomicReferenceArray = f;
        int id = (int) ((b - 1) & Thread.currentThread().getId());
        segment.b = 0;
        segment.e = true;
        while (true) {
            g gVar = (g) atomicReferenceArray.get(id);
            g gVar2 = a;
            if (gVar != gVar2) {
                int i = gVar != null ? gVar.c : 0;
                if (i < 65536) {
                    segment.f = gVar;
                    segment.c = i + 8192;
                    while (!atomicReferenceArray.compareAndSet(id, gVar, segment)) {
                        if (atomicReferenceArray.get(id) != gVar) {
                            break;
                        }
                    }
                    return;
                }
                if (d <= 0) {
                    return;
                }
                segment.b = 0;
                segment.e = true;
                int i2 = c;
                int id2 = (int) ((i2 - 1) & Thread.currentThread().getId());
                AtomicReferenceArray atomicReferenceArray2 = g;
                int i3 = 0;
                while (true) {
                    g gVar3 = (g) atomicReferenceArray2.get(id2);
                    if (gVar3 != gVar2) {
                        int i4 = (gVar3 != null ? gVar3.c : 0) + 8192;
                        if (i4 <= e) {
                            segment.f = gVar3;
                            segment.c = i4;
                            while (!atomicReferenceArray2.compareAndSet(id2, gVar3, segment)) {
                                if (atomicReferenceArray2.get(id2) != gVar3) {
                                    break;
                                }
                            }
                            return;
                        }
                        if (i3 >= i2) {
                            return;
                        }
                        i3++;
                        id2 = (id2 + 1) & (i2 - 1);
                    }
                }
            }
        }
    }

    public static final g b() {
        g gVar;
        g gVar2;
        AtomicReferenceArray atomicReferenceArray = f;
        int id = (int) ((b - 1) & Thread.currentThread().getId());
        do {
            gVar = a;
            gVar2 = (g) atomicReferenceArray.getAndSet(id, gVar);
        } while (Intrinsics.b(gVar2, gVar));
        if (gVar2 != null) {
            atomicReferenceArray.set(id, gVar2.f);
            gVar2.f = null;
            gVar2.c = 0;
            return gVar2;
        }
        atomicReferenceArray.set(id, null);
        if (d <= 0) {
            return new g();
        }
        AtomicReferenceArray atomicReferenceArray2 = g;
        int i = c;
        int id2 = (int) (Thread.currentThread().getId() & (i - 1));
        int i2 = 0;
        while (true) {
            g gVar3 = (g) atomicReferenceArray2.getAndSet(id2, gVar);
            if (!Intrinsics.b(gVar3, gVar)) {
                if (gVar3 != null) {
                    atomicReferenceArray2.set(id2, gVar3.f);
                    gVar3.f = null;
                    gVar3.c = 0;
                    return gVar3;
                }
                atomicReferenceArray2.set(id2, null);
                if (i2 >= i) {
                    return new g();
                }
                id2 = (id2 + 1) & (i - 1);
                i2++;
            }
        }
    }
}
