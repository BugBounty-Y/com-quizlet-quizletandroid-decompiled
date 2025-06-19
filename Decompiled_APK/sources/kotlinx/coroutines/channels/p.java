package kotlinx.coroutines.channels;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicReferenceArray;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends kotlinx.coroutines.internal.q {
    public final h e;
    public final /* synthetic */ AtomicReferenceArray f;

    public p(long j, p pVar, h hVar, int i) {
        super(j, pVar, i);
        this.e = hVar;
        this.f = new AtomicReferenceArray(j.b * 2);
    }

    @Override // kotlinx.coroutines.internal.q
    public final int g() {
        return j.b;
    }

    /* JADX WARN: Code restructure failed: missing block: B:34:0x0059, code lost:
    
        n(r5, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x005c, code lost:
    
        if (r0 == false) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x005e, code lost:
    
        kotlin.jvm.internal.Intrinsics.d(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0061, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:?, code lost:
    
        return;
     */
    @Override // kotlinx.coroutines.internal.q
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h(int r5, kotlin.coroutines.CoroutineContext r6) {
        /*
            r4 = this;
            int r6 = kotlinx.coroutines.channels.j.b
            if (r5 < r6) goto L6
            r0 = 1
            goto L7
        L6:
            r0 = 0
        L7:
            if (r0 == 0) goto La
            int r5 = r5 - r6
        La:
            java.util.concurrent.atomic.AtomicReferenceArray r6 = r4.f
            int r1 = r5 * 2
            r6.get(r1)
        L11:
            java.lang.Object r6 = r4.l(r5)
            boolean r1 = r6 instanceof kotlinx.coroutines.J0
            kotlinx.coroutines.channels.h r2 = r4.e
            r3 = 0
            if (r1 != 0) goto L62
            boolean r1 = r6 instanceof kotlinx.coroutines.channels.y
            if (r1 == 0) goto L21
            goto L62
        L21:
            com.android.billingclient.api.a r1 = kotlinx.coroutines.channels.j.j
            if (r6 == r1) goto L59
            com.android.billingclient.api.a r1 = kotlinx.coroutines.channels.j.k
            if (r6 != r1) goto L2a
            goto L59
        L2a:
            com.android.billingclient.api.a r1 = kotlinx.coroutines.channels.j.g
            if (r6 == r1) goto L11
            com.android.billingclient.api.a r1 = kotlinx.coroutines.channels.j.f
            if (r6 != r1) goto L33
            goto L11
        L33:
            com.android.billingclient.api.a r5 = kotlinx.coroutines.channels.j.i
            if (r6 == r5) goto L7c
            com.android.billingclient.api.a r5 = kotlinx.coroutines.channels.j.d
            if (r6 != r5) goto L3c
            goto L7c
        L3c:
            com.android.billingclient.api.a r5 = kotlinx.coroutines.channels.j.l
            if (r6 != r5) goto L41
            goto L7c
        L41:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "unexpected state: "
            r0.<init>(r1)
            r0.append(r6)
            java.lang.String r6 = r0.toString()
            java.lang.String r6 = r6.toString()
            r5.<init>(r6)
            throw r5
        L59:
            r4.n(r5, r3)
            if (r0 == 0) goto L7c
            kotlin.jvm.internal.Intrinsics.d(r2)
            return
        L62:
            if (r0 == 0) goto L67
            com.android.billingclient.api.a r1 = kotlinx.coroutines.channels.j.j
            goto L69
        L67:
            com.android.billingclient.api.a r1 = kotlinx.coroutines.channels.j.k
        L69:
            boolean r6 = r4.k(r5, r6, r1)
            if (r6 == 0) goto L11
            r4.n(r5, r3)
            r6 = r0 ^ 1
            r4.m(r5, r6)
            if (r0 == 0) goto L7c
            kotlin.jvm.internal.Intrinsics.d(r2)
        L7c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.p.h(int, kotlin.coroutines.CoroutineContext):void");
    }

    public final boolean k(int i, Object obj, Object obj2) {
        AtomicReferenceArray atomicReferenceArray = this.f;
        int i2 = (i * 2) + 1;
        while (!atomicReferenceArray.compareAndSet(i2, obj, obj2)) {
            if (atomicReferenceArray.get(i2) != obj) {
                return false;
            }
        }
        return true;
    }

    public final Object l(int i) {
        return this.f.get((i * 2) + 1);
    }

    public final void m(int i, boolean z) {
        if (z) {
            h hVar = this.e;
            Intrinsics.d(hVar);
            hVar.L((this.c * j.b) + i);
        }
        i();
    }

    public final void n(int i, Object obj) {
        this.f.set(i * 2, obj);
    }

    public final void o(int i, C1472a c1472a) {
        this.f.set((i * 2) + 1, c1472a);
    }
}
