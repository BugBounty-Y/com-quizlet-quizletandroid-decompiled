package androidx.compose.material;

import androidx.compose.animation.core.InterfaceC0256n;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3236q0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0575s {
    public final c0 a;
    public final d0 b;
    public final InterfaceC0256n c;
    public final InterfaceC0773a0 f;
    public final F0 j;
    public final InterfaceC0773a0 k;
    public final InterfaceC0773a0 l;
    public final C0573p m;
    public final F d = new F();
    public final r e = new r(this);
    public final androidx.compose.runtime.E g = C0776c.q(new C0567j(this, 4));
    public final androidx.compose.runtime.E h = C0776c.q(new C0567j(this, 2));
    public final F0 i = C0776c.v(Float.NaN);

    public C0575s(f0 f0Var, c0 c0Var, d0 d0Var, InterfaceC0256n interfaceC0256n) {
        this.a = c0Var;
        this.b = d0Var;
        this.c = interfaceC0256n;
        this.f = C0776c.z(f0Var);
        C0776c.p(androidx.compose.runtime.V.f, new C0567j(this, 3));
        this.j = C0776c.v(DefinitionKt.NO_Float_VALUE);
        this.k = C0776c.z(null);
        this.l = C0776c.z(new G(kotlin.collections.V.c()));
        this.m = new C0573p(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0082  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00be  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(androidx.compose.foundation.u0 r7, androidx.compose.material.C0574q r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r9 instanceof androidx.compose.material.C0566i
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.material.i r0 = (androidx.compose.material.C0566i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.material.i r0 = new androidx.compose.material.i
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1056964608(0x3f000000, float:0.5)
            r4 = 1
            if (r2 == 0) goto L35
            if (r2 != r4) goto L2d
            androidx.compose.material.s r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2b
            goto L54
        L2b:
            r8 = move-exception
            goto L90
        L2d:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            androidx.compose.material.F r9 = r6.d     // Catch: java.lang.Throwable -> L8e
            androidx.compose.material.l r2 = new androidx.compose.material.l     // Catch: java.lang.Throwable -> L8e
            r5 = 0
            r2.<init>(r8, r6, r5)     // Catch: java.lang.Throwable -> L8e
            r0.j = r6     // Catch: java.lang.Throwable -> L8e
            r0.m = r4     // Catch: java.lang.Throwable -> L8e
            r9.getClass()     // Catch: java.lang.Throwable -> L8a
            androidx.compose.material.E r8 = new androidx.compose.material.E     // Catch: java.lang.Throwable -> L8a
            r8.<init>(r7, r9, r2, r5)     // Catch: java.lang.Throwable -> L8a
            java.lang.Object r7 = kotlinx.coroutines.E.m(r8, r0)     // Catch: java.lang.Throwable -> L8a
            if (r7 != r1) goto L53
            return r1
        L53:
            r7 = r6
        L54:
            androidx.compose.material.G r8 = r7.d()
            float r9 = r7.e()
            java.lang.Object r8 = r8.a(r9)
            if (r8 == 0) goto L85
            float r9 = r7.e()
            androidx.compose.material.G r0 = r7.d()
            float r0 = r0.c(r8)
            float r9 = r9 - r0
            float r9 = java.lang.Math.abs(r9)
            int r9 = (r9 > r3 ? 1 : (r9 == r3 ? 0 : -1))
            if (r9 > 0) goto L85
            r9 = r8
            androidx.compose.material.f0 r9 = (androidx.compose.material.f0) r9
            java.lang.Boolean r9 = java.lang.Boolean.TRUE
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L85
            r7.h(r8)
        L85:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L88:
            r8 = r7
            goto L8c
        L8a:
            r7 = move-exception
            goto L88
        L8c:
            r7 = r6
            goto L90
        L8e:
            r8 = move-exception
            goto L8c
        L90:
            androidx.compose.material.G r9 = r7.d()
            float r0 = r7.e()
            java.lang.Object r9 = r9.a(r0)
            if (r9 == 0) goto Lc1
            float r0 = r7.e()
            androidx.compose.material.G r1 = r7.d()
            float r1 = r1.c(r9)
            float r0 = r0 - r1
            float r0 = java.lang.Math.abs(r0)
            int r0 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r0 > 0) goto Lc1
            r0 = r9
            androidx.compose.material.f0 r0 = (androidx.compose.material.f0) r0
            java.lang.Boolean r0 = java.lang.Boolean.TRUE
            boolean r0 = r0.booleanValue()
            if (r0 == 0) goto Lc1
            r7.h(r9)
        Lc1:
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.C0575s.a(androidx.compose.foundation.u0, androidx.compose.material.q, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r10v3, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(java.lang.Object r7, androidx.compose.foundation.u0 r8, androidx.compose.material.C0560c r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r10 instanceof androidx.compose.material.C0570m
            if (r0 == 0) goto L13
            r0 = r10
            androidx.compose.material.m r0 = (androidx.compose.material.C0570m) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.material.m r0 = new androidx.compose.material.m
            r0.<init>(r6, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1056964608(0x3f000000, float:0.5)
            r5 = 1
            if (r2 == 0) goto L37
            if (r2 != r5) goto L2f
            androidx.compose.material.s r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L2c
            goto L61
        L2c:
            r8 = move-exception
            goto L9e
        L2f:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            androidx.compose.material.G r10 = r6.d()
            java.lang.Object r10 = r10.a
            boolean r10 = r10.containsKey(r7)
            if (r10 == 0) goto Ld3
            androidx.compose.material.F r10 = r6.d     // Catch: java.lang.Throwable -> L9c
            androidx.compose.material.o r2 = new androidx.compose.material.o     // Catch: java.lang.Throwable -> L9c
            r2.<init>(r6, r7, r9, r3)     // Catch: java.lang.Throwable -> L9c
            r0.j = r6     // Catch: java.lang.Throwable -> L9c
            r0.m = r5     // Catch: java.lang.Throwable -> L9c
            r10.getClass()     // Catch: java.lang.Throwable -> L98
            androidx.compose.material.E r7 = new androidx.compose.material.E     // Catch: java.lang.Throwable -> L98
            r7.<init>(r8, r10, r2, r3)     // Catch: java.lang.Throwable -> L98
            java.lang.Object r7 = kotlinx.coroutines.E.m(r7, r0)     // Catch: java.lang.Throwable -> L98
            if (r7 != r1) goto L60
            return r1
        L60:
            r7 = r6
        L61:
            r7.i(r3)
            androidx.compose.material.G r8 = r7.d()
            float r9 = r7.e()
            java.lang.Object r8 = r8.a(r9)
            if (r8 == 0) goto Ld6
            float r9 = r7.e()
            androidx.compose.material.G r10 = r7.d()
            float r10 = r10.c(r8)
            float r9 = r9 - r10
            float r9 = java.lang.Math.abs(r9)
            int r9 = (r9 > r4 ? 1 : (r9 == r4 ? 0 : -1))
            if (r9 > 0) goto Ld6
            r9 = r8
            androidx.compose.material.f0 r9 = (androidx.compose.material.f0) r9
            java.lang.Boolean r9 = java.lang.Boolean.TRUE
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto Ld6
            r7.h(r8)
            goto Ld6
        L96:
            r8 = r7
            goto L9a
        L98:
            r7 = move-exception
            goto L96
        L9a:
            r7 = r6
            goto L9e
        L9c:
            r8 = move-exception
            goto L9a
        L9e:
            r7.i(r3)
            androidx.compose.material.G r9 = r7.d()
            float r10 = r7.e()
            java.lang.Object r9 = r9.a(r10)
            if (r9 == 0) goto Ld2
            float r10 = r7.e()
            androidx.compose.material.G r0 = r7.d()
            float r0 = r0.c(r9)
            float r10 = r10 - r0
            float r10 = java.lang.Math.abs(r10)
            int r10 = (r10 > r4 ? 1 : (r10 == r4 ? 0 : -1))
            if (r10 > 0) goto Ld2
            r10 = r9
            androidx.compose.material.f0 r10 = (androidx.compose.material.f0) r10
            java.lang.Boolean r10 = java.lang.Boolean.TRUE
            boolean r10 = r10.booleanValue()
            if (r10 == 0) goto Ld2
            r7.h(r9)
        Ld2:
            throw r8
        Ld3:
            r6.h(r7)
        Ld6:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.C0575s.b(java.lang.Object, androidx.compose.foundation.u0, androidx.compose.material.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object c(float f, float f2, Object obj) {
        G gD = d();
        float fC = gD.c(obj);
        float fFloatValue = ((Number) this.b.invoke()).floatValue();
        if (fC != f && !Float.isNaN(fC)) {
            c0 c0Var = this.a;
            if (fC < f) {
                if (f2 >= fFloatValue) {
                    Object objB = gD.b(f, true);
                    Intrinsics.d(objB);
                    return objB;
                }
                Object objB2 = gD.b(f, true);
                Intrinsics.d(objB2);
                if (f >= Math.abs(Math.abs(((Number) c0Var.invoke(Float.valueOf(Math.abs(gD.c(objB2) - fC)))).floatValue()) + fC)) {
                    return objB2;
                }
            } else {
                if (f2 <= (-fFloatValue)) {
                    Object objB3 = gD.b(f, false);
                    Intrinsics.d(objB3);
                    return objB3;
                }
                Object objB4 = gD.b(f, false);
                Intrinsics.d(objB4);
                float fAbs = Math.abs(fC - Math.abs(((Number) c0Var.invoke(Float.valueOf(Math.abs(fC - gD.c(objB4))))).floatValue()));
                if (f >= DefinitionKt.NO_Float_VALUE ? f <= fAbs : Math.abs(f) >= fAbs) {
                    return objB4;
                }
            }
        }
        return obj;
    }

    public final G d() {
        return (G) ((L0) this.l).getValue();
    }

    public final float e() {
        return this.i.i();
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v2, types: [java.lang.Object, java.util.Map] */
    public final float f(float f) {
        float fE = (Float.isNaN(e()) ? DefinitionKt.NO_Float_VALUE : e()) + f;
        Float fZ = CollectionsKt.Z(d().a.values());
        float fFloatValue = fZ != null ? fZ.floatValue() : Float.NaN;
        Float fX = CollectionsKt.X(d().a.values());
        return kotlin.ranges.l.b(fE, fFloatValue, fX != null ? fX.floatValue() : Float.NaN);
    }

    public final float g() {
        if (Float.isNaN(e())) {
            throw new IllegalStateException("The offset was read before being initialized. Did you access the offset in a phase before layout, like effects or composition?");
        }
        return e();
    }

    public final void h(Object obj) {
        ((L0) this.f).setValue(obj);
    }

    public final void i(Object obj) {
        ((L0) this.k).setValue(obj);
    }

    public final Object j(float f, kotlin.coroutines.jvm.internal.c cVar) {
        Object value = ((L0) this.f).getValue();
        Object objC = c(g(), f, value);
        if (Boolean.TRUE.booleanValue()) {
            Object objC2 = AbstractC3236q0.c(this, objC, f, cVar);
            return objC2 == kotlin.coroutines.intrinsics.a.a ? objC2 : Unit.a;
        }
        Object objC3 = AbstractC3236q0.c(this, value, f, cVar);
        return objC3 == kotlin.coroutines.intrinsics.a.a ? objC3 : Unit.a;
    }
}
