package androidx.activity.compose;

import android.graphics.Canvas;
import android.view.DragEvent;
import androidx.activity.L;
import androidx.collection.z;
import androidx.compose.animation.C0282i;
import androidx.compose.animation.C0292t;
import androidx.compose.animation.O;
import androidx.compose.animation.b0;
import androidx.compose.animation.core.C0254m;
import androidx.compose.animation.core.C0272v0;
import androidx.compose.animation.core.P;
import androidx.compose.animation.q0;
import androidx.compose.foundation.gestures.C0333k;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.gestures.I0;
import androidx.compose.foundation.gestures.L0;
import androidx.compose.foundation.layout.B0;
import androidx.compose.foundation.layout.w0;
import androidx.compose.foundation.layout.x0;
import androidx.compose.foundation.layout.y0;
import androidx.compose.foundation.layout.z0;
import androidx.compose.foundation.text.C0481c;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.C0502j0;
import androidx.compose.foundation.text.C0519s0;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.N0;
import androidx.compose.foundation.text.selection.C0531l;
import androidx.compose.foundation.text.selection.C0534o;
import androidx.compose.foundation.text.selection.C0536q;
import androidx.compose.material.C0582z;
import androidx.compose.material3.C0624g4;
import androidx.compose.material3.C0718s2;
import androidx.compose.material3.C0724t2;
import androidx.compose.material3.EnumC0630h4;
import androidx.compose.material3.F3;
import androidx.compose.material3.X4;
import androidx.compose.material3.internal.C0660y;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.S;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.graphics.Z;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.p0;
import androidx.compose.ui.platform.C0971v;
import androidx.compose.ui.platform.ViewOnDragListenerC0963q0;
import androidx.compose.ui.text.AbstractC1013n;
import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.D;
import androidx.compose.ui.text.G;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.I;
import androidx.compose.ui.text.K;
import androidx.compose.ui.text.input.A;
import androidx.glance.session.C1231i;
import androidx.lifecycle.J;
import androidx.lifecycle.T;
import androidx.paging.C1325l;
import androidx.paging.F;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.N4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class g extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public g(androidx.compose.ui.focus.t tVar, androidx.compose.ui.focus.j jVar, Function1 function1) {
        super(1);
        this.a = 23;
        this.b = tVar;
        this.c = jVar;
        this.d = (kotlin.jvm.internal.r) function1;
    }

    /* JADX WARN: Type inference failed for: r0v159, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        I iB;
        I iB2;
        I iB3;
        boolean zBooleanValue;
        switch (this.a) {
            case 0:
                L l = (L) this.b;
                J j = (J) this.c;
                i iVar = (i) this.d;
                l.a(j, iVar);
                return new c(iVar, 1);
            case 1:
                L l2 = (L) this.b;
                J j2 = (J) this.c;
                r rVar = (r) this.d;
                l2.a(j2, rVar);
                return new c(rVar, 2);
            case 2:
                return new C0282i((androidx.compose.runtime.snapshots.q) this.b, this.c, (C0292t) this.d, 0);
            case 3:
                S s = (S) obj;
                C0272v0 c0272v0 = (C0272v0) this.b;
                s.b(c0272v0 != null ? ((Number) c0272v0.getValue()).floatValue() : 1.0f);
                C0272v0 c0272v02 = (C0272v0) this.c;
                s.m(c0272v02 != null ? ((Number) c0272v02.getValue()).floatValue() : 1.0f);
                s.o(c0272v02 != null ? ((Number) c0272v02.getValue()).floatValue() : 1.0f);
                C0272v0 c0272v03 = (C0272v0) this.d;
                s.x(c0272v03 != null ? ((Z) c0272v03.getValue()).a : Z.b);
                return Unit.a;
            case 4:
                int iOrdinal = ((O) obj).ordinal();
                Z z = null;
                b0 b0Var = (b0) this.d;
                if (iOrdinal == 0) {
                    q0 q0Var = b0Var.a;
                } else if (iOrdinal == 1) {
                    z = (Z) this.b;
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    q0 q0Var2 = b0Var.a;
                }
                return new Z(z != null ? z.a : Z.b);
            case 5:
                float fFloatValue = ((Number) obj).floatValue();
                C0333k c0333k = (C0333k) this.b;
                float f = c0333k.p ? 1.0f : -1.0f;
                L0 l0 = c0333k.o;
                long jD = l0.d(l0.g(f * fFloatValue));
                L0 l02 = ((I0) this.d).a;
                float f2 = l0.f(l0.d(L0.a(l02, l02.h, jD, 1))) * f;
                if (Math.abs(f2) < Math.abs(fFloatValue)) {
                    E.j((InterfaceC5025j0) this.c, "Scroll animation cancelled because scroll was not consumed (" + f2 + " < " + fFloatValue + ')', null);
                }
                return Unit.a;
            case 6:
                V v = (V) obj;
                w0 w0Var = (w0) this.b;
                boolean z2 = w0Var.p;
                M m = (M) this.d;
                W w = (W) this.c;
                if (z2) {
                    V.f(v, w, m.m0(w0Var.n), m.m0(w0Var.o));
                } else {
                    V.d(v, w, m.m0(w0Var.n), m.m0(w0Var.o));
                }
                return Unit.a;
            case 7:
                V v2 = (V) obj;
                x0 x0Var = (x0) this.b;
                long j3 = ((androidx.compose.ui.unit.h) x0Var.n.invoke((M) this.c)).a;
                boolean z3 = x0Var.o;
                W w2 = (W) this.d;
                if (z3) {
                    V.g(v2, w2, (int) (j3 >> 32), (int) (j3 & 4294967295L));
                } else {
                    V.i(v2, w2, (int) (j3 >> 32), (int) (j3 & 4294967295L), null, 12);
                }
                return Unit.a;
            case 8:
                V v3 = (V) obj;
                y0 y0Var = (y0) this.b;
                boolean z4 = y0Var.r;
                M m2 = (M) this.d;
                W w3 = (W) this.c;
                if (z4) {
                    V.f(v3, w3, m2.m0(y0Var.n), m2.m0(y0Var.o));
                } else {
                    V.d(v3, w3, m2.m0(y0Var.n), m2.m0(y0Var.o));
                }
                return Unit.a;
            case 9:
                B0 b0 = (B0) this.d;
                z0 z0Var = b0.n;
                M m3 = (M) this.c;
                V.d((V) obj, (W) this.b, m3.m0(z0Var.b(m3.getLayoutDirection())), m3.m0(b0.n.d()));
                return Unit.a;
            case 10:
                A a = (A) obj;
                ((InterfaceC0773a0) this.c).setValue(a);
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.d;
                boolean zB = Intrinsics.b((String) interfaceC0773a0.getValue(), a.a.a);
                C0995g c0995g = a.a;
                interfaceC0773a0.setValue(c0995g.a);
                if (!zB) {
                    ((Function1) this.b).invoke(c0995g.a);
                }
                return Unit.a;
            case 11:
                androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
                C0492h0 c0492h0 = (C0492h0) this.b;
                K0 k0D = c0492h0.d();
                if (k0D != null) {
                    InterfaceC0858s interfaceC0858sO = dVar.e0().o();
                    long j4 = ((K) ((androidx.compose.runtime.L0) c0492h0.x).getValue()).a;
                    long j5 = ((K) ((androidx.compose.runtime.L0) c0492h0.y).getValue()).a;
                    long j6 = c0492h0.w;
                    boolean zB2 = K.b(j4);
                    H h = k0D.a;
                    androidx.compose.ui.text.input.s sVar = (androidx.compose.ui.text.input.s) this.d;
                    G g = h.a;
                    com.google.android.gms.cloudmessaging.k kVar = c0492h0.v;
                    if (!zB2) {
                        kVar.f(j6);
                        int iP = sVar.p(K.e(j4));
                        int iP2 = sVar.p(K.d(j4));
                        if (iP != iP2) {
                            interfaceC0858sO.d(h.k(iP, iP2), kVar);
                        }
                    } else if (K.b(j5)) {
                        A a2 = (A) this.c;
                        if (!K.b(a2.b)) {
                            kVar.f(j6);
                            long j7 = a2.b;
                            int iP3 = sVar.p(K.e(j7));
                            int iP4 = sVar.p(K.d(j7));
                            if (iP3 != iP4) {
                                interfaceC0858sO.d(h.k(iP3, iP4), kVar);
                            }
                        }
                    } else {
                        long jC = g.b.c();
                        C0861v c0861v = new C0861v(jC);
                        if (jC == 16) {
                            c0861v = null;
                        }
                        long j8 = c0861v != null ? c0861v.a : C0861v.b;
                        kVar.f(C0861v.b(j8, C0861v.d(j8) * 0.2f));
                        int iP5 = sVar.p(K.e(j5));
                        int iP6 = sVar.p(K.d(j5));
                        if (iP5 != iP6) {
                            interfaceC0858sO.d(h.k(iP5, iP6), kVar);
                        }
                    }
                    boolean z5 = h.d() && g.f != 3;
                    if (z5) {
                        long j9 = h.c;
                        androidx.compose.ui.geometry.c cVarA = R4.a(0L, T4.a((int) (j9 >> 32), (int) (j9 & 4294967295L)));
                        interfaceC0858sO.e();
                        InterfaceC0858s.k(interfaceC0858sO, cVarA);
                    }
                    D d = g.b.a;
                    androidx.compose.ui.text.style.j jVar = d.m;
                    androidx.compose.ui.text.style.n nVar = d.a;
                    if (jVar == null) {
                        jVar = androidx.compose.ui.text.style.j.b;
                    }
                    androidx.compose.ui.text.style.j jVar2 = jVar;
                    U u = d.n;
                    if (u == null) {
                        u = U.d;
                    }
                    U u2 = u;
                    androidx.compose.ui.graphics.drawscope.e eVar = d.p;
                    if (eVar == null) {
                        eVar = androidx.compose.ui.graphics.drawscope.g.a;
                    }
                    androidx.compose.ui.graphics.drawscope.e eVar2 = eVar;
                    try {
                        AbstractC0857q abstractC0857qC = nVar.c();
                        androidx.compose.ui.text.style.l lVar = androidx.compose.ui.text.style.l.a;
                        androidx.compose.ui.text.o oVar = h.b;
                        if (abstractC0857qC != null) {
                            androidx.compose.ui.text.o.h(oVar, interfaceC0858sO, abstractC0857qC, nVar != lVar ? nVar.a() : 1.0f, u2, jVar2, eVar2);
                        } else {
                            androidx.compose.ui.text.o.g(oVar, interfaceC0858sO, nVar != lVar ? nVar.b() : C0861v.b, u2, jVar2, eVar2);
                        }
                        if (z5) {
                            interfaceC0858sO.q();
                        }
                    } catch (Throwable th) {
                        if (z5) {
                            interfaceC0858sO.q();
                        }
                        throw th;
                    }
                }
                return Unit.a;
            case 12:
                androidx.compose.ui.text.input.H h2 = (androidx.compose.ui.text.input.H) ((kotlin.jvm.internal.J) this.d).a;
                A aF = ((com.quizlet.data.repository.explanations.myexplanations.a) this.b).f((List) obj);
                if (h2 != null) {
                    h2.a(null, aF);
                }
                ((androidx.compose.foundation.text.D) this.c).invoke(aF);
                return Unit.a;
            case 13:
                C0519s0 c0519s0 = (C0519s0) obj;
                C0985e c0985e = (C0985e) this.c;
                Object obj2 = c0985e.a;
                I iB4 = ((AbstractC1013n) obj2).b();
                D dC = null;
                D d2 = iB4 != null ? iB4.a : null;
                H0 h0 = ((C0502j0) this.d).a;
                D dC2 = (!((h0.i() & 1) != 0) || (iB3 = ((AbstractC1013n) obj2).b()) == null) ? null : iB3.b;
                ((N0) this.b).getClass();
                if (d2 != null) {
                    dC2 = d2.c(dC2);
                }
                D dC3 = ((h0.i() & 2) == 0 || (iB2 = ((AbstractC1013n) obj2).b()) == null) ? null : iB2.c;
                if (dC2 != null) {
                    dC3 = dC2.c(dC3);
                }
                if ((h0.i() & 4) != 0 && (iB = ((AbstractC1013n) obj2).b()) != null) {
                    dC = iB.d;
                }
                if (dC3 != null) {
                    dC = dC3.c(dC);
                }
                if (dC != null) {
                    c0519s0.a.c(dC, c0985e.b, c0985e.c);
                }
                return Unit.a;
            case 14:
                C0534o c0534o = (C0534o) obj;
                int length = c0534o.f.a.a.a.length();
                z zVar = (z) this.c;
                ((C0531l) this.b).getClass();
                C0531l.n(zVar, (C0536q) this.d, c0534o, 0, length);
                return Unit.a;
            case 15:
                V v4 = (V) obj;
                boolean zA0 = ((M) this.b).a0();
                C0582z c0582z = (C0582z) this.c;
                float fC = zA0 ? c0582z.n.d().c(c0582z.n.g.getValue()) : c0582z.n.g();
                EnumC0320d0 enumC0320d0 = c0582z.p;
                float f3 = enumC0320d0 == EnumC0320d0.b ? fC : 0.0f;
                if (enumC0320d0 != EnumC0320d0.a) {
                    fC = 0.0f;
                }
                V.d(v4, (W) this.d, kotlin.math.c.b(f3), kotlin.math.c.b(fC));
                return Unit.a;
            case 16:
                C0254m c0254m = (C0254m) obj;
                float fFloatValue2 = ((Number) ((androidx.compose.runtime.L0) c0254m.e).getValue()).floatValue();
                kotlin.jvm.internal.G g2 = (kotlin.jvm.internal.G) this.b;
                float f4 = fFloatValue2 - g2.a;
                X4 x4 = (X4) this.c;
                float fB = x4.b();
                x4.d(fB + f4);
                float fAbs = Math.abs(fB - x4.b());
                g2.a = ((Number) ((androidx.compose.runtime.L0) c0254m.e).getValue()).floatValue();
                ((kotlin.jvm.internal.G) this.d).a = ((Number) c0254m.a.b.invoke(c0254m.f)).floatValue();
                if (Math.abs(f4 - fAbs) > 0.5f) {
                    c0254m.a();
                }
                return Unit.a;
            case 17:
                float fFloatValue3 = ((Number) obj).floatValue();
                F3 f32 = (F3) this.c;
                E.A((C) this.b, null, null, new C0724t2(f32, fFloatValue3, null), 3).Q(new C0718s2(f32, (Function0) this.d, 1));
                return Unit.a;
            case 18:
                return new C0624g4((EnumC0630h4) obj, (androidx.compose.ui.unit.b) this.b, (Function1) this.c, (Function1) this.d);
            case 19:
                V v5 = (V) obj;
                boolean zA02 = ((M) this.b).a0();
                C0660y c0660y = (C0660y) this.c;
                float fC2 = zA02 ? c0660y.n.h().c(((androidx.compose.runtime.E) c0660y.n.h).getValue()) : c0660y.n.s();
                EnumC0320d0 enumC0320d02 = c0660y.p;
                float f5 = enumC0320d02 == EnumC0320d0.b ? fC2 : 0.0f;
                if (enumC0320d02 != EnumC0320d0.a) {
                    fC2 = 0.0f;
                }
                V.d(v5, (W) this.d, kotlin.math.c.b(f5), kotlin.math.c.b(fC2));
                return Unit.a;
            case 20:
                androidx.camera.camera2.internal.D d3 = new androidx.camera.camera2.internal.D((InterfaceC0773a0) this.d, 1);
                J j10 = (J) this.c;
                T t = (T) this.b;
                t.f(j10, d3);
                return new P(8, t, d3);
            case 21:
                androidx.compose.runtime.saveable.f fVar = (androidx.compose.runtime.saveable.f) this.b;
                androidx.collection.I i = fVar.b;
                Object obj3 = this.c;
                if (i.b(obj3)) {
                    throw new IllegalArgumentException(("Key " + obj3 + " was used multiple times ").toString());
                }
                fVar.a.remove(obj3);
                androidx.collection.I i2 = fVar.b;
                androidx.compose.runtime.saveable.i iVar2 = (androidx.compose.runtime.saveable.i) this.d;
                i2.j(obj3, iVar2);
                return new C0282i(fVar, obj3, iVar2, 1);
            case EventType.WINDOW_STATE /* 22 */:
                androidx.compose.ui.node.q0 q0Var3 = (androidx.compose.ui.node.q0) obj;
                androidx.compose.ui.draganddrop.e eVar3 = (androidx.compose.ui.draganddrop.e) q0Var3;
                if (((ViewOnDragListenerC0963q0) ((C0971v) AbstractC0910f.w((androidx.compose.ui.draganddrop.e) this.c)).getDragAndDropManager()).b.contains(eVar3)) {
                    DragEvent dragEvent = (DragEvent) ((com.google.android.gms.internal.instantapps.a) this.d).b;
                    if (N4.f(eVar3, Q4.c(dragEvent.getX(), dragEvent.getY()))) {
                        ((kotlin.jvm.internal.J) this.b).a = q0Var3;
                        return p0.c;
                    }
                }
                return p0.a;
            case EventType.AUDIO /* 23 */:
                androidx.compose.ui.focus.t tVar = (androidx.compose.ui.focus.t) obj;
                if (Intrinsics.b(tVar, (androidx.compose.ui.focus.t) this.b)) {
                    zBooleanValue = false;
                } else {
                    if (Intrinsics.b(tVar, ((androidx.compose.ui.focus.j) this.c).f)) {
                        throw new IllegalStateException("Focus search landed at the root.");
                    }
                    zBooleanValue = ((Boolean) ((kotlin.jvm.internal.r) this.d).invoke(tVar)).booleanValue();
                }
                return Boolean.valueOf(zBooleanValue);
            case EventType.VIDEO /* 24 */:
                InterfaceC0858s interfaceC0858sO2 = ((androidx.compose.ui.graphics.drawscope.d) obj).e0().o();
                androidx.compose.ui.viewinterop.p pVar = (androidx.compose.ui.viewinterop.p) this.b;
                if (pVar.getView().getVisibility() != 8) {
                    pVar.u = true;
                    C0971v c0971v = ((androidx.compose.ui.node.E) this.c).i;
                    if (c0971v == null) {
                        c0971v = null;
                    }
                    if (c0971v != null) {
                        Canvas canvasA = AbstractC0845e.a(interfaceC0858sO2);
                        c0971v.getAndroidViewsHandler$ui_release().getClass();
                        ((androidx.compose.ui.viewinterop.p) this.d).draw(canvasA);
                    }
                    pVar.u = false;
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                androidx.glance.session.K k = (androidx.glance.session.K) this.b;
                long jA = k.a();
                androidx.glance.session.I i3 = (androidx.glance.session.I) this.c;
                if (kotlin.time.b.c(jA, i3.b) < 0) {
                    AtomicReference atomicReference = k.b;
                    C0481c c0481c = new C0481c(2, i3.b);
                    while (true) {
                        Object obj4 = atomicReference.get();
                        Object objInvoke = c0481c.invoke(obj4);
                        while (!atomicReference.compareAndSet(obj4, objInvoke)) {
                            if (atomicReference.get() != obj4) {
                                break;
                            }
                        }
                    }
                }
                E.A(k, null, null, new androidx.glance.session.E((C1231i) this.d, null), 3);
                return Unit.a;
            case EventType.CDN /* 26 */:
                return com.quizlet.data.repository.user.a.b((com.quizlet.data.repository.user.a) this.b, (C1325l) obj, (F) this.c, (F) this.d);
            default:
                app.cash.sqldelight.a transactionWithResult = (app.cash.sqldelight.a) obj;
                Intrinsics.checkNotNullParameter(transactionWithResult, "$this$transactionWithResult");
                com.quizlet.shared.persistence.db.g gVar = (com.quizlet.shared.persistence.db.g) this.b;
                app.cash.sqldelight.driver.android.i iVar3 = (app.cash.sqldelight.driver.android.i) gVar.b;
                com.quizlet.shared.persistence.db.e eVar4 = (com.quizlet.shared.persistence.db.e) this.d;
                iVar3.a(-499700455, "UPDATE dbStudiableMetadata\n  SET model = ?\n  WHERE  (\n    studiableContainerId = ?\n    AND studiableContainerType = ?\n    AND studiableMetadataType = ?\n  )", new com.quizlet.shared.persistence.db.d(eVar4, gVar, 0));
                iVar3.a(-499700454, "INSERT OR IGNORE INTO dbStudiableMetadata (studiableContainerId, studiableContainerType, studiableMetadataType, model)\n  VALUES (\n    ?,\n    ?,\n     ?,\n     ?\n  )", new com.quizlet.shared.persistence.db.d(eVar4, gVar, 1));
                return iVar3.f(-499700453, "SELECT model\n  FROM dbStudiableMetadata\n  WHERE (\n      studiableContainerId = ?\n      AND studiableContainerType = ?\n      AND studiableMetadataType = ?\n  )", (androidx.credentials.playservices.controllers.BeginSignIn.c) this.c, 3, new com.quizlet.shared.persistence.db.d(eVar4, gVar, 2));
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(Object obj, Object obj2, Object obj3, int i) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }
}
