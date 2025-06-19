package kotlinx.coroutines.channels;

import kotlin.jvm.internal.C4956o;

/* loaded from: classes3.dex */
public final /* synthetic */ class d extends C4956o implements kotlin.jvm.functions.c {
    public static final d a = new d(3, h.class, "registerSelectForReceive", "registerSelectForReceive(Lkotlinx/coroutines/selects/SelectInstance;Ljava/lang/Object;)V", 0);

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0075, code lost:
    
        return kotlin.Unit.a;
     */
    @Override // kotlin.jvm.functions.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r9, java.lang.Object r10, java.lang.Object r11) {
        /*
            r8 = this;
            r0 = r9
            kotlinx.coroutines.channels.h r0 = (kotlinx.coroutines.channels.h) r0
            r5 = r10
            kotlinx.coroutines.selects.f r5 = (kotlinx.coroutines.selects.f) r5
            java.util.concurrent.atomic.AtomicLongFieldUpdater r9 = kotlinx.coroutines.channels.h.b
            r0.getClass()
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r9 = kotlinx.coroutines.channels.h.g
            java.lang.Object r9 = r9.get(r0)
            kotlinx.coroutines.channels.p r9 = (kotlinx.coroutines.channels.p) r9
        L13:
            boolean r10 = r0.y()
            if (r10 == 0) goto L20
            com.android.billingclient.api.a r9 = kotlinx.coroutines.channels.j.l
            kotlinx.coroutines.selects.e r5 = (kotlinx.coroutines.selects.e) r5
            r5.e = r9
            goto L73
        L20:
            java.util.concurrent.atomic.AtomicLongFieldUpdater r10 = kotlinx.coroutines.channels.h.c
            long r3 = r10.getAndIncrement(r0)
            int r10 = kotlinx.coroutines.channels.j.b
            long r10 = (long) r10
            long r1 = r3 / r10
            long r10 = r3 % r10
            int r10 = (int) r10
            long r6 = r9.c
            int r11 = (r6 > r1 ? 1 : (r6 == r1 ? 0 : -1))
            if (r11 == 0) goto L3e
            kotlinx.coroutines.channels.p r11 = r0.q(r1, r9)
            if (r11 != 0) goto L3b
            goto L13
        L3b:
            r1 = r11
        L3c:
            r2 = r10
            goto L40
        L3e:
            r1 = r9
            goto L3c
        L40:
            java.lang.Object r9 = r0.J(r1, r2, r3, r5)
            r11 = r1
            com.android.billingclient.api.a r10 = kotlinx.coroutines.channels.j.m
            if (r9 != r10) goto L57
            boolean r9 = r5 instanceof kotlinx.coroutines.J0
            if (r9 == 0) goto L50
            kotlinx.coroutines.J0 r5 = (kotlinx.coroutines.J0) r5
            goto L51
        L50:
            r5 = 0
        L51:
            if (r5 == 0) goto L73
            r5.a(r11, r2)
            goto L73
        L57:
            com.android.billingclient.api.a r10 = kotlinx.coroutines.channels.j.o
            if (r9 != r10) goto L68
            long r9 = r0.v()
            int r9 = (r3 > r9 ? 1 : (r3 == r9 ? 0 : -1))
            if (r9 >= 0) goto L66
            r11.a()
        L66:
            r9 = r11
            goto L13
        L68:
            com.android.billingclient.api.a r10 = kotlinx.coroutines.channels.j.n
            if (r9 == r10) goto L76
            r11.a()
            kotlinx.coroutines.selects.e r5 = (kotlinx.coroutines.selects.e) r5
            r5.e = r9
        L73:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L76:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "unexpected"
            r9.<init>(r10)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.channels.d.invoke(java.lang.Object, java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
