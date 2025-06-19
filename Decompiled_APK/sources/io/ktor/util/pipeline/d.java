package io.ktor.util.pipeline;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class d {

    @NotNull
    private volatile /* synthetic */ Object _interceptors;
    public final ArrayList a;
    public int b;
    public boolean c;
    public androidx.sqlite.db.a d;

    public d(androidx.sqlite.db.a... phases) {
        Intrinsics.checkNotNullParameter(phases, "phases");
        new io.ktor.util.e();
        this.a = B.k(Arrays.copyOf(phases, phases.length));
        this._interceptors = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x005a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.lang.Object r13, java.lang.Object r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r12 = this;
            kotlin.coroutines.CoroutineContext r0 = r15.getContext()
            java.lang.Object r1 = r12._interceptors
            java.util.List r1 = (java.util.List) r1
            r2 = 1
            if (r1 != 0) goto L99
            int r1 = r12.b
            r3 = 0
            r4 = 0
            if (r1 != 0) goto L1b
            kotlin.collections.K r1 = kotlin.collections.K.a
            r12._interceptors = r1
            r12.c = r4
            r12.d = r3
            goto L99
        L1b:
            java.util.ArrayList r5 = r12.a
            if (r1 != r2) goto L4f
            int r1 = kotlin.collections.B.i(r5)
            if (r1 < 0) goto L4f
            r6 = r4
        L26:
            java.lang.Object r7 = r5.get(r6)
            boolean r8 = r7 instanceof io.ktor.util.pipeline.c
            if (r8 == 0) goto L31
            io.ktor.util.pipeline.c r7 = (io.ktor.util.pipeline.c) r7
            goto L32
        L31:
            r7 = r3
        L32:
            if (r7 != 0) goto L35
            goto L4a
        L35:
            java.util.List r8 = r7.c
            boolean r8 = r8.isEmpty()
            if (r8 != 0) goto L4a
            java.util.List r1 = r7.c
            r7.d = r2
            r12._interceptors = r1
            r12.c = r4
            androidx.sqlite.db.a r1 = r7.a
            r12.d = r1
            goto L99
        L4a:
            if (r6 == r1) goto L4f
            int r6 = r6 + 1
            goto L26
        L4f:
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            int r6 = kotlin.collections.B.i(r5)
            if (r6 < 0) goto L93
            r7 = r4
        L5b:
            java.lang.Object r8 = r5.get(r7)
            boolean r9 = r8 instanceof io.ktor.util.pipeline.c
            if (r9 == 0) goto L66
            io.ktor.util.pipeline.c r8 = (io.ktor.util.pipeline.c) r8
            goto L67
        L66:
            r8 = r3
        L67:
            if (r8 != 0) goto L6a
            goto L8e
        L6a:
            java.lang.String r9 = "destination"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r9)
            java.util.List r8 = r8.c
            int r9 = r1.size()
            int r10 = r8.size()
            int r10 = r10 + r9
            r1.ensureCapacity(r10)
            int r9 = r8.size()
            r10 = r4
        L82:
            if (r10 >= r9) goto L8e
            java.lang.Object r11 = r8.get(r10)
            r1.add(r11)
            int r10 = r10 + 1
            goto L82
        L8e:
            if (r7 == r6) goto L93
            int r7 = r7 + 1
            goto L5b
        L93:
            r12._interceptors = r1
            r12.c = r4
            r12.d = r3
        L99:
            r12.c = r2
            java.lang.Object r1 = r12._interceptors
            java.util.List r1 = (java.util.List) r1
            kotlin.jvm.internal.Intrinsics.d(r1)
            boolean r2 = r12.d()
            java.lang.String r3 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r3)
            java.lang.String r3 = "interceptors"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r3)
            java.lang.String r3 = "subject"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r14, r3)
            java.lang.String r3 = "coroutineContext"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)
            boolean r3 = io.ktor.util.pipeline.f.a
            if (r3 != 0) goto Lc7
            if (r2 == 0) goto Lc1
            goto Lc7
        Lc1:
            io.ktor.util.pipeline.l r0 = new io.ktor.util.pipeline.l
            r0.<init>(r14, r13, r1)
            goto Lcd
        Lc7:
            io.ktor.util.pipeline.b r2 = new io.ktor.util.pipeline.b
            r2.<init>(r13, r1, r14, r0)
            r0 = r2
        Lcd:
            java.lang.Object r13 = r0.a(r14, r15)
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.util.pipeline.d.a(java.lang.Object, java.lang.Object, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final c b(androidx.sqlite.db.a aVar) {
        ArrayList arrayList = this.a;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            Object obj = arrayList.get(i);
            if (obj == aVar) {
                c cVar = new c(aVar, i.a);
                arrayList.set(i, cVar);
                return cVar;
            }
            if (obj instanceof c) {
                c cVar2 = (c) obj;
                if (cVar2.a == aVar) {
                    return cVar2;
                }
            }
        }
        return null;
    }

    public final int c(androidx.sqlite.db.a aVar) {
        ArrayList arrayList = this.a;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            Object obj = arrayList.get(i);
            if (obj == aVar || ((obj instanceof c) && ((c) obj).a == aVar)) {
                return i;
            }
        }
        return -1;
    }

    public abstract boolean d();

    public final boolean e(androidx.sqlite.db.a aVar) {
        ArrayList arrayList = this.a;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            Object obj = arrayList.get(i);
            if (obj == aVar) {
                return true;
            }
            if ((obj instanceof c) && ((c) obj).a == aVar) {
                return true;
            }
        }
        return false;
    }

    public final void f(androidx.sqlite.db.a phase, kotlin.jvm.functions.c interceptor) {
        Intrinsics.checkNotNullParameter(phase, "phase");
        Intrinsics.checkNotNullParameter(interceptor, "block");
        c cVarB = b(phase);
        if (cVarB == null) {
            throw new androidx.concurrent.futures.b("Phase " + phase + " was not registered for this pipeline");
        }
        List list = (List) this._interceptors;
        if (!this.a.isEmpty() && list != null && !this.c && (!(list instanceof kotlin.jvm.internal.markers.a) || (list instanceof kotlin.jvm.internal.markers.c))) {
            if (Intrinsics.b(this.d, phase)) {
                list.add(interceptor);
            } else if (Intrinsics.b(phase, CollectionsKt.U(this.a)) || c(phase) == B.i(this.a)) {
                c cVarB2 = b(phase);
                Intrinsics.d(cVarB2);
                Intrinsics.checkNotNullParameter(interceptor, "interceptor");
                if (cVarB2.d) {
                    cVarB2.c = CollectionsKt.y0(cVarB2.c);
                    cVarB2.d = false;
                }
                cVarB2.c.add(interceptor);
                list.add(interceptor);
            }
            this.b++;
            return;
        }
        Intrinsics.checkNotNullParameter(interceptor, "interceptor");
        if (cVarB.d) {
            cVarB.c = CollectionsKt.y0(cVarB.c);
            cVarB.d = false;
        }
        cVarB.c.add(interceptor);
        this.b++;
        this._interceptors = null;
        this.c = false;
        this.d = null;
    }
}
