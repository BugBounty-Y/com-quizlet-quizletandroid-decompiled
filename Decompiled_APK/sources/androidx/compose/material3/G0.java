package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.material3.internal.C0654s;
import androidx.compose.material3.internal.C0657v;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class G0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.d {
    public final /* synthetic */ AbstractC0655t a;
    public final /* synthetic */ C0657v b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ C0654s d;
    public final /* synthetic */ Long e;
    public final /* synthetic */ C0716s0 f;
    public final /* synthetic */ InterfaceC0764y3 g;
    public final /* synthetic */ C0699p0 h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G0(AbstractC0655t abstractC0655t, C0657v c0657v, Function1 function1, C0654s c0654s, Long l, C0716s0 c0716s0, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0) {
        super(4);
        this.a = abstractC0655t;
        this.b = c0657v;
        this.c = function1;
        this.d = c0654s;
        this.e = l;
        this.f = c0716s0;
        this.g = interfaceC0764y3;
        this.h = c0699p0;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x004c  */
    @Override // kotlin.jvm.functions.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r11, java.lang.Object r12, java.lang.Object r13, java.lang.Object r14) {
        /*
            r10 = this;
            androidx.compose.foundation.lazy.b r11 = (androidx.compose.foundation.lazy.C0422b) r11
            java.lang.Number r12 = (java.lang.Number) r12
            int r12 = r12.intValue()
            r8 = r13
            androidx.compose.runtime.l r8 = (androidx.compose.runtime.InterfaceC0806l) r8
            java.lang.Number r14 = (java.lang.Number) r14
            int r13 = r14.intValue()
            r14 = r13 & 6
            if (r14 != 0) goto L23
            r14 = r8
            androidx.compose.runtime.p r14 = (androidx.compose.runtime.C0814p) r14
            boolean r14 = r14.f(r11)
            if (r14 == 0) goto L20
            r14 = 4
            goto L21
        L20:
            r14 = 2
        L21:
            r14 = r14 | r13
            goto L24
        L23:
            r14 = r13
        L24:
            r13 = r13 & 48
            if (r13 != 0) goto L37
            r13 = r8
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            boolean r13 = r13.d(r12)
            if (r13 == 0) goto L34
            r13 = 32
            goto L36
        L34:
            r13 = 16
        L36:
            r14 = r14 | r13
        L37:
            r13 = r14 & 147(0x93, float:2.06E-43)
            r14 = 146(0x92, float:2.05E-43)
            if (r13 != r14) goto L4c
            r13 = r8
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            boolean r14 = r13.x()
            if (r14 != 0) goto L47
            goto L4c
        L47:
            r13.Q()
            goto Lde
        L4c:
            androidx.compose.material3.internal.t r13 = r10.a
            androidx.compose.material3.internal.u r13 = (androidx.compose.material3.internal.C0656u) r13
            r13.getClass()
            androidx.compose.material3.internal.v r14 = r10.b
            if (r12 > 0) goto L59
        L57:
            r0 = r14
            goto L73
        L59:
            long r0 = r14.e
            java.time.Instant r14 = java.time.Instant.ofEpochMilli(r0)
            java.time.ZoneId r0 = androidx.compose.material3.internal.C0656u.d
            java.time.ZonedDateTime r14 = r14.atZone(r0)
            java.time.LocalDate r14 = r14.toLocalDate()
            long r0 = (long) r12
            java.time.LocalDate r12 = r14.plusMonths(r0)
            androidx.compose.material3.internal.v r14 = r13.d(r12)
            goto L57
        L73:
            androidx.compose.ui.q r11 = androidx.compose.foundation.lazy.C0422b.b(r11)
            androidx.compose.ui.i r12 = androidx.compose.ui.b.a
            r13 = 0
            androidx.compose.ui.layout.K r12 = androidx.compose.foundation.layout.AbstractC0409s.e(r12, r13)
            r13 = r8
            androidx.compose.runtime.p r13 = (androidx.compose.runtime.C0814p) r13
            int r14 = r13.P
            androidx.compose.runtime.j0 r1 = r13.l()
            androidx.compose.ui.q r11 = androidx.compose.ui.a.c(r8, r11)
            androidx.compose.ui.node.j r2 = androidx.compose.ui.node.InterfaceC0915k.D0
            r2.getClass()
            androidx.compose.ui.node.i r2 = androidx.compose.ui.node.C0914j.b
            r13.b0()
            boolean r3 = r13.O
            if (r3 == 0) goto L9d
            r13.k(r2)
            goto La0
        L9d:
            r13.l0()
        La0:
            androidx.compose.ui.node.h r2 = androidx.compose.ui.node.C0914j.f
            androidx.compose.runtime.C0776c.E(r8, r12, r2)
            androidx.compose.ui.node.h r12 = androidx.compose.ui.node.C0914j.e
            androidx.compose.runtime.C0776c.E(r8, r1, r12)
            androidx.compose.ui.node.h r12 = androidx.compose.ui.node.C0914j.g
            boolean r1 = r13.O
            if (r1 != 0) goto Lbe
            java.lang.Object r1 = r13.I()
            java.lang.Integer r2 = java.lang.Integer.valueOf(r14)
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r2)
            if (r1 != 0) goto Lc1
        Lbe:
            android.support.v4.media.session.a.z(r14, r13, r14, r12)
        Lc1:
            androidx.compose.ui.node.h r12 = androidx.compose.ui.node.C0914j.d
            androidx.compose.runtime.C0776c.E(r8, r11, r12)
            androidx.compose.material3.internal.s r11 = r10.d
            androidx.compose.material3.p0 r7 = r10.h
            androidx.compose.material3.s0 r5 = r10.f
            r9 = 221184(0x36000, float:3.09945E-40)
            kotlin.jvm.functions.Function1 r1 = r10.c
            long r2 = r11.d
            java.lang.Long r4 = r10.e
            androidx.compose.material3.y3 r6 = r10.g
            androidx.compose.material3.Z0.g(r0, r1, r2, r4, r5, r6, r7, r8, r9)
            r11 = 1
            r13.p(r11)
        Lde:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.G0.invoke(java.lang.Object, java.lang.Object, java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
