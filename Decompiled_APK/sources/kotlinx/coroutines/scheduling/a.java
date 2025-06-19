package kotlinx.coroutines.scheduling;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.jvm.internal.J;

/* loaded from: classes3.dex */
public final class a extends Thread {
    public static final /* synthetic */ AtomicIntegerFieldUpdater i = AtomicIntegerFieldUpdater.newUpdater(a.class, "workerCtl$volatile");
    public final m a;
    public final J b;
    public b c;
    public long d;
    public long e;
    public int f;
    public boolean g;
    public final /* synthetic */ c h;
    private volatile int indexInArray;
    private volatile Object nextParkedWorker;
    private volatile /* synthetic */ int workerCtl$volatile;

    public a(c cVar, int i2) {
        this.h = cVar;
        setDaemon(true);
        setContextClassLoader(cVar.getClass().getClassLoader());
        this.a = new m();
        this.b = new J();
        this.c = b.d;
        this.nextParkedWorker = c.k;
        int iNanoTime = (int) System.nanoTime();
        this.f = iNanoTime == 0 ? 42 : iNanoTime;
        f(i2);
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0043, code lost:
    
        r13 = kotlinx.coroutines.scheduling.m.d.get(r3);
        r0 = kotlinx.coroutines.scheduling.m.c.get(r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x004f, code lost:
    
        if (r13 == r0) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0057, code lost:
    
        if (kotlinx.coroutines.scheduling.m.e.get(r3) != 0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x005a, code lost:
    
        r0 = r0 - 1;
        r1 = r3.c(r0, true);
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0060, code lost:
    
        if (r1 == null) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0062, code lost:
    
        r2 = r1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlinx.coroutines.scheduling.i a(boolean r13) {
        /*
            r12 = this;
            kotlinx.coroutines.scheduling.b r0 = r12.c
            kotlinx.coroutines.scheduling.b r1 = kotlinx.coroutines.scheduling.b.a
            r2 = 0
            kotlinx.coroutines.scheduling.m r3 = r12.a
            r4 = 1
            kotlinx.coroutines.scheduling.c r5 = r12.h
            if (r0 != r1) goto Le
            goto L88
        Le:
            java.util.concurrent.atomic.AtomicLongFieldUpdater r0 = kotlinx.coroutines.scheduling.c.i
        L10:
            kotlinx.coroutines.scheduling.c r7 = r12.h
            long r8 = r0.get(r7)
            r10 = 9223367638808264704(0x7ffffc0000000000, double:NaN)
            long r10 = r10 & r8
            r1 = 42
            long r10 = r10 >> r1
            int r1 = (int) r10
            if (r1 != 0) goto L75
            r3.getClass()
        L25:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r13 = kotlinx.coroutines.scheduling.m.b
            java.lang.Object r0 = r13.get(r3)
            kotlinx.coroutines.scheduling.i r0 = (kotlinx.coroutines.scheduling.i) r0
            if (r0 != 0) goto L30
            goto L43
        L30:
            boolean r1 = r0.b
            if (r1 != r4) goto L43
        L34:
            boolean r1 = r13.compareAndSet(r3, r0, r2)
            if (r1 == 0) goto L3c
            r2 = r0
            goto L63
        L3c:
            java.lang.Object r1 = r13.get(r3)
            if (r1 == r0) goto L34
            goto L25
        L43:
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r13 = kotlinx.coroutines.scheduling.m.d
            int r13 = r13.get(r3)
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r0 = kotlinx.coroutines.scheduling.m.c
            int r0 = r0.get(r3)
        L4f:
            if (r13 == r0) goto L63
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r1 = kotlinx.coroutines.scheduling.m.e
            int r1 = r1.get(r3)
            if (r1 != 0) goto L5a
            goto L63
        L5a:
            int r0 = r0 + (-1)
            kotlinx.coroutines.scheduling.i r1 = r3.c(r0, r4)
            if (r1 == 0) goto L4f
            r2 = r1
        L63:
            if (r2 != 0) goto L74
            kotlinx.coroutines.scheduling.f r13 = r5.f
            java.lang.Object r13 = r13.d()
            kotlinx.coroutines.scheduling.i r13 = (kotlinx.coroutines.scheduling.i) r13
            if (r13 != 0) goto L73
            kotlinx.coroutines.scheduling.i r13 = r12.i(r4)
        L73:
            return r13
        L74:
            return r2
        L75:
            r10 = 4398046511104(0x40000000000, double:2.1729236899484E-311)
            long r10 = r8 - r10
            java.util.concurrent.atomic.AtomicLongFieldUpdater r6 = kotlinx.coroutines.scheduling.c.i
            boolean r1 = r6.compareAndSet(r7, r8, r10)
            if (r1 == 0) goto L10
            kotlinx.coroutines.scheduling.b r0 = kotlinx.coroutines.scheduling.b.a
            r12.c = r0
        L88:
            if (r13 == 0) goto Lbc
            int r13 = r5.a
            int r13 = r13 * 2
            int r13 = r12.d(r13)
            if (r13 != 0) goto L95
            goto L96
        L95:
            r4 = 0
        L96:
            if (r4 == 0) goto L9f
            kotlinx.coroutines.scheduling.i r13 = r12.e()
            if (r13 == 0) goto L9f
            return r13
        L9f:
            r3.getClass()
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r13 = kotlinx.coroutines.scheduling.m.b
            java.lang.Object r13 = r13.getAndSet(r3, r2)
            kotlinx.coroutines.scheduling.i r13 = (kotlinx.coroutines.scheduling.i) r13
            if (r13 != 0) goto Lb0
            kotlinx.coroutines.scheduling.i r13 = r3.b()
        Lb0:
            if (r13 == 0) goto Lb3
            return r13
        Lb3:
            if (r4 != 0) goto Lc3
            kotlinx.coroutines.scheduling.i r13 = r12.e()
            if (r13 == 0) goto Lc3
            return r13
        Lbc:
            kotlinx.coroutines.scheduling.i r13 = r12.e()
            if (r13 == 0) goto Lc3
            return r13
        Lc3:
            r13 = 3
            kotlinx.coroutines.scheduling.i r13 = r12.i(r13)
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.scheduling.a.a(boolean):kotlinx.coroutines.scheduling.i");
    }

    public final int b() {
        return this.indexInArray;
    }

    public final Object c() {
        return this.nextParkedWorker;
    }

    public final int d(int i2) {
        int i3 = this.f;
        int i4 = i3 ^ (i3 << 13);
        int i5 = i4 ^ (i4 >> 17);
        int i6 = i5 ^ (i5 << 5);
        this.f = i6;
        int i7 = i2 - 1;
        return (i7 & i2) == 0 ? i6 & i7 : (i6 & SubsamplingScaleImageView.TILE_SIZE_AUTO) % i2;
    }

    public final i e() {
        int iD = d(2);
        c cVar = this.h;
        if (iD == 0) {
            i iVar = (i) cVar.e.d();
            return iVar != null ? iVar : (i) cVar.f.d();
        }
        i iVar2 = (i) cVar.f.d();
        return iVar2 != null ? iVar2 : (i) cVar.e.d();
    }

    public final void f(int i2) {
        StringBuilder sb = new StringBuilder();
        sb.append(this.h.d);
        sb.append("-worker-");
        sb.append(i2 == 0 ? "TERMINATED" : String.valueOf(i2));
        setName(sb.toString());
        this.indexInArray = i2;
    }

    public final void g(Object obj) {
        this.nextParkedWorker = obj;
    }

    public final boolean h(b bVar) {
        b bVar2 = this.c;
        boolean z = bVar2 == b.a;
        if (z) {
            c.i.addAndGet(this.h, 4398046511104L);
        }
        if (bVar2 != bVar) {
            this.c = bVar;
        }
        return z;
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x006b, code lost:
    
        r7 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00a0, code lost:
    
        r7 = -2;
        r23 = r6;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlinx.coroutines.scheduling.i i(int r26) {
        /*
            Method dump skipped, instructions count: 264
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.scheduling.a.i(int):kotlinx.coroutines.scheduling.i");
    }

    /* JADX WARN: Code restructure failed: missing block: B:128:0x0004, code lost:
    
        continue;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x0004, code lost:
    
        continue;
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x0004, code lost:
    
        continue;
     */
    @Override // java.lang.Thread, java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() {
        /*
            Method dump skipped, instructions count: 429
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.scheduling.a.run():void");
    }
}
