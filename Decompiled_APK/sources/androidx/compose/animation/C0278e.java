package androidx.compose.animation;

import android.view.InputDevice;
import android.view.KeyEvent;
import android.view.View;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.B0;
import androidx.compose.animation.core.C0;
import androidx.compose.animation.core.E0;
import androidx.compose.animation.core.w0;
import androidx.compose.animation.core.x0;
import androidx.compose.animation.core.z0;
import androidx.compose.foundation.gestures.C0327h;
import androidx.compose.foundation.gestures.C0337m;
import androidx.compose.foundation.gestures.C0339n;
import androidx.compose.foundation.gestures.C0354v;
import androidx.compose.foundation.gestures.C0358x;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.gestures.I0;
import androidx.compose.foundation.gestures.o1;
import androidx.compose.foundation.layout.RunnableC0403o0;
import androidx.compose.foundation.layout.S0;
import androidx.compose.foundation.lazy.grid.C0427b;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.C0504k0;
import androidx.compose.foundation.text.C0513p;
import androidx.compose.foundation.text.C0547v;
import androidx.compose.foundation.text.N0;
import androidx.compose.foundation.text.selection.C0536q;
import androidx.compose.foundation.text.selection.InterfaceC0530k;
import androidx.compose.material.C0573p;
import androidx.compose.material.C0575s;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import androidx.compose.ui.platform.Y0;
import androidx.compose.ui.text.C0985e;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T5;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.MatchResult;

/* renamed from: androidx.compose.animation.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0278e extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0278e(int i, Object obj, Object obj2) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    /* JADX WARN: Type inference failed for: r1v23, types: [java.lang.Object, java.util.List] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.text.H h;
        C0985e c0985eC;
        C0850j c0850jK;
        int i = 3;
        int i2 = 5;
        int i3 = 6;
        int i4 = 4;
        int i5 = 2;
        float fC = DefinitionKt.NO_Float_VALUE;
        int i6 = 0;
        zE = false;
        zE = false;
        zE = false;
        zE = false;
        zE = false;
        boolean zE = false;
        z = false;
        z = false;
        boolean z = false;
        int i7 = 1;
        Object obj2 = this.b;
        Object obj3 = this.c;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                float fI = ((J) obj3).c.i();
                androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) obj2;
                v.getClass();
                long jB = P5.b(0, 0);
                androidx.compose.ui.layout.V.a(v, w);
                w.s0(androidx.compose.ui.unit.h.d(jB, w.e), fI, null);
                return Unit.a;
            case 1:
                x0 x0Var = (x0) obj;
                Object objA = x0Var.a();
                androidx.collection.I i8 = ((C0292t) obj2).d;
                W0 w0 = (W0) i8.f(objA);
                long j = w0 != null ? ((androidx.compose.ui.unit.j) w0.getValue()).a : 0L;
                W0 w02 = (W0) i8.f(x0Var.c());
                long j2 = w02 != null ? ((androidx.compose.ui.unit.j) w02.getValue()).a : 0L;
                n0 n0Var = (n0) ((C0291s) obj3).c.getValue();
                if (n0Var != null) {
                    androidx.compose.animation.core.D d = (androidx.compose.animation.core.D) n0Var.a.invoke(new androidx.compose.ui.unit.j(j), new androidx.compose.ui.unit.j(j2));
                    if (d != null) {
                        return d;
                    }
                }
                return AbstractC0240f.q(7, null);
            case 2:
                androidx.compose.animation.core.N n = (androidx.compose.animation.core.N) obj2;
                androidx.compose.animation.core.J j3 = (androidx.compose.animation.core.J) obj3;
                n.a.b(j3);
                ((L0) n.b).setValue(Boolean.TRUE);
                return new androidx.compose.animation.core.P(i6, n, j3);
            case 3:
                kotlinx.coroutines.E.A((kotlinx.coroutines.C) obj2, null, kotlinx.coroutines.D.d, new B0((E0) obj3, null), 1);
                return new C0();
            case 4:
                E0 e0 = (E0) obj2;
                E0 e02 = (E0) obj3;
                e0.j.add(e02);
                return new androidx.compose.animation.core.P(i7, e0, e02);
            case 5:
                return new androidx.compose.animation.core.P(i5, (E0) obj2, (w0) obj3);
            case 6:
                E0 e03 = (E0) obj2;
                z0 z0Var = (z0) obj3;
                e03.i.add(z0Var);
                return new androidx.compose.animation.core.P(i, e03, z0Var);
            case 7:
                androidx.compose.ui.node.G g = (androidx.compose.ui.node.G) obj;
                g.b();
                androidx.compose.ui.graphics.drawscope.d.A(g, ((androidx.compose.ui.graphics.K) obj2).a, (androidx.compose.ui.graphics.X) obj3, DefinitionKt.NO_Float_VALUE, null, 60);
                return Unit.a;
            case 8:
                androidx.compose.ui.node.G g2 = (androidx.compose.ui.node.G) obj;
                g2.b();
                androidx.compose.ui.graphics.drawscope.d.A(g2, (C0850j) obj2, (androidx.compose.ui.graphics.X) obj3, DefinitionKt.NO_Float_VALUE, null, 60);
                return Unit.a;
            case 9:
                ((androidx.compose.foundation.interaction.l) obj2).a((androidx.compose.foundation.interaction.j) obj3);
                return Unit.a;
            case 10:
                ((androidx.compose.runtime.collection.b) ((com.google.firebase.platforminfo.c) obj2).a).n((C0327h) obj3);
                return Unit.a;
            case 11:
                com.quizlet.data.interactor.course.e eVar = (com.quizlet.data.interactor.course.e) obj2;
                V4.h(eVar, (androidx.compose.ui.input.pointer.n) obj);
                androidx.compose.foundation.gestures.Q q = (androidx.compose.foundation.gestures.Q) obj3;
                float fE = ((Y0) AbstractC0910f.i(q, AbstractC0955m0.q)).e();
                long jB2 = T5.b(fE, fE);
                if (androidx.compose.ui.unit.o.b(jB2) <= DefinitionKt.NO_Float_VALUE || androidx.compose.ui.unit.o.c(jB2) <= DefinitionKt.NO_Float_VALUE) {
                    W4.f("maximumVelocity should be a positive value. You specified=" + ((Object) androidx.compose.ui.unit.o.g(jB2)));
                    throw null;
                }
                float fB = androidx.compose.ui.unit.o.b(jB2);
                androidx.compose.foundation.lazy.grid.m mVar = (androidx.compose.foundation.lazy.grid.m) eVar.b;
                float fB2 = mVar.b(fB);
                float fC2 = androidx.compose.ui.unit.o.c(jB2);
                androidx.compose.foundation.lazy.grid.m mVar2 = (androidx.compose.foundation.lazy.grid.m) eVar.c;
                long jB3 = T5.b(fB2, mVar2.b(fC2));
                androidx.compose.ui.input.pointer.util.a[] aVarArr = (androidx.compose.ui.input.pointer.util.a[]) mVar.c;
                C4930v.o(aVarArr, null, 0, aVarArr.length);
                mVar.b = 0;
                androidx.compose.ui.input.pointer.util.a[] aVarArr2 = (androidx.compose.ui.input.pointer.util.a[]) mVar2.c;
                C4930v.o(aVarArr2, null, 0, aVarArr2.length);
                mVar2.b = 0;
                eVar.a = 0L;
                kotlinx.coroutines.channels.h hVar = q.t;
                if (hVar != null) {
                    androidx.compose.foundation.gestures.S s = androidx.compose.foundation.gestures.U.a;
                    float fB3 = Float.isNaN(androidx.compose.ui.unit.o.b(jB3)) ? 0.0f : androidx.compose.ui.unit.o.b(jB3);
                    if (!Float.isNaN(androidx.compose.ui.unit.o.c(jB3))) {
                        fC = androidx.compose.ui.unit.o.c(jB3);
                    }
                    hVar.o(new C0358x(T5.b(fB3, fC)));
                }
                return Unit.a;
            case 12:
                androidx.compose.foundation.gestures.Y y = (androidx.compose.foundation.gestures.Y) obj3;
                long jI = androidx.compose.ui.geometry.b.i(((C0354v) obj).a, y.C ? -1.0f : 1.0f);
                EnumC0320d0 enumC0320d0 = y.y;
                androidx.compose.foundation.gestures.S s2 = androidx.compose.foundation.gestures.U.a;
                float fE2 = enumC0320d0 == EnumC0320d0.a ? androidx.compose.ui.geometry.b.e(jI) : androidx.compose.ui.geometry.b.d(jI);
                C0337m c0337m = (C0337m) obj2;
                switch (c0337m.a) {
                    case 0:
                        ((C0339n) c0337m.b).a.invoke(Float.valueOf(fE2));
                        break;
                    case 1:
                        C0575s c0575s = (C0575s) c0337m.b;
                        C0573p c0573p = c0575s.m;
                        float f = c0575s.f(fE2);
                        C0575s c0575s2 = c0573p.a;
                        c0575s2.i.j(f);
                        c0575s2.j.j(DefinitionKt.NO_Float_VALUE);
                        break;
                    default:
                        androidx.work.impl.model.t tVar = (androidx.work.impl.model.t) c0337m.b;
                        androidx.compose.material3.internal.r rVar = (androidx.compose.material3.internal.r) tVar.n;
                        float fR = tVar.r(fE2);
                        androidx.work.impl.model.t tVar2 = rVar.a;
                        ((F0) tVar2.j).j(fR);
                        ((F0) tVar2.k).j(DefinitionKt.NO_Float_VALUE);
                        break;
                }
                return Unit.a;
            case 13:
                long j4 = ((C0354v) obj).a;
                long jA = ((androidx.compose.foundation.gestures.L0) obj3).d == EnumC0320d0.b ? androidx.compose.ui.geometry.b.a(DefinitionKt.NO_Float_VALUE, 1, j4) : androidx.compose.ui.geometry.b.a(DefinitionKt.NO_Float_VALUE, 2, j4);
                androidx.compose.foundation.gestures.L0 l0 = ((I0) obj2).a;
                l0.g = 1;
                androidx.compose.foundation.C0 c0 = l0.b;
                if (c0 == null || !(l0.a.d() || l0.a.b())) {
                    androidx.compose.foundation.gestures.L0.a(l0, l0.h, jA, 1);
                } else {
                    c0.f(jA, l0.g, l0.j);
                }
                return Unit.a;
            case 14:
                ((Number) obj).longValue();
                o1 o1Var = (o1) obj2;
                float f2 = o1Var.e;
                o1Var.e = DefinitionKt.NO_Float_VALUE;
                ((Function1) obj3).invoke(Float.valueOf(f2));
                return Unit.a;
            case 15:
                S0 s0 = (S0) obj2;
                View view = (View) obj3;
                if (s0.u == 0) {
                    WeakHashMap weakHashMap = androidx.core.view.V.a;
                    RunnableC0403o0 runnableC0403o0 = s0.v;
                    androidx.core.view.L.m(view, runnableC0403o0);
                    if (view.isAttachedToWindow()) {
                        view.requestApplyInsets();
                    }
                    view.addOnAttachStateChangeListener(runnableC0403o0);
                    androidx.core.view.V.r(view, runnableC0403o0);
                }
                s0.u++;
                return new androidx.compose.animation.core.P(i4, s0, view);
            case 16:
                com.android.billingclient.api.s sVarB = ((androidx.compose.foundation.lazy.grid.x) obj2).b(((Number) obj).intValue());
                ?? r1 = sVarB.c;
                ArrayList arrayList = new ArrayList(r1.size());
                int size = r1.size();
                int i9 = sVarB.b;
                int i10 = 0;
                while (i6 < size) {
                    int i11 = (int) ((C0427b) r1.get(i6)).a;
                    arrayList.add(new Pair(Integer.valueOf(i9), new androidx.compose.ui.unit.a(((androidx.compose.foundation.lazy.grid.m) obj3).c(i10, i11))));
                    i9++;
                    i10 += i11;
                    i6++;
                }
                return arrayList;
            case 17:
                androidx.compose.foundation.lazy.layout.l0 l0Var = (androidx.compose.foundation.lazy.layout.l0) obj2;
                l0Var.c.remove(obj3);
                return new androidx.compose.animation.core.P(i2, l0Var, obj3);
            case 18:
                androidx.compose.ui.text.input.A a = (androidx.compose.ui.text.input.A) obj;
                if (!Intrinsics.b((androidx.compose.ui.text.input.A) obj2, a)) {
                    ((Function1) obj3).invoke(a);
                }
                return Unit.a;
            case 19:
                long j5 = ((androidx.compose.ui.geometry.b) obj).a;
                androidx.compose.ui.text.H h2 = (androidx.compose.ui.text.H) ((InterfaceC0773a0) obj2).getValue();
                if (h2 != null) {
                    ((Function1) obj3).invoke(Integer.valueOf(h2.b.e(j5)));
                }
                return Unit.a;
            case 20:
                KeyEvent keyEvent = ((androidx.compose.ui.input.key.b) obj).a;
                if (((C0492h0) obj2).a() == androidx.compose.foundation.text.V.b && keyEvent.getKeyCode() == 4 && androidx.compose.ui.input.key.c.c(keyEvent) == 1) {
                    ((androidx.compose.foundation.text.selection.i0) obj3).g(null);
                    z = true;
                }
                return Boolean.valueOf(z);
            case 21:
                androidx.compose.ui.layout.V v2 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayListN = AbstractC0484d0.n((List) obj2, (Function0) ((C0504k0) obj3).b);
                if (arrayListN != null) {
                    int size2 = arrayListN.size();
                    for (int i12 = 0; i12 < size2; i12++) {
                        Pair pair = (Pair) arrayListN.get(i12);
                        androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) pair.a;
                        Function0 function0 = (Function0) pair.b;
                        androidx.compose.ui.layout.V.e(v2, w2, function0 != null ? ((androidx.compose.ui.unit.h) function0.invoke()).a : 0L);
                    }
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                KeyEvent keyEvent2 = ((androidx.compose.ui.input.key.b) obj).a;
                InputDevice device = keyEvent2.getDevice();
                if (device != null && device.supportsSource(513) && !device.isVirtual() && androidx.compose.ui.input.key.c.c(keyEvent2) == 2 && keyEvent2.getSource() != 257) {
                    androidx.compose.ui.focus.h hVar2 = (androidx.compose.ui.focus.h) obj2;
                    if (AbstractC0484d0.m(19, keyEvent2)) {
                        zE = ((androidx.compose.ui.focus.j) hVar2).e(5);
                    } else if (AbstractC0484d0.m(20, keyEvent2)) {
                        zE = ((androidx.compose.ui.focus.j) hVar2).e(6);
                    } else if (AbstractC0484d0.m(21, keyEvent2)) {
                        zE = ((androidx.compose.ui.focus.j) hVar2).e(3);
                    } else if (AbstractC0484d0.m(22, keyEvent2)) {
                        zE = ((androidx.compose.ui.focus.j) hVar2).e(4);
                    } else if (AbstractC0484d0.m(23, keyEvent2)) {
                        Q0 q0 = ((C0492h0) obj3).c;
                        if (q0 != null) {
                            ((C0957n0) q0).b();
                        }
                        zE = true;
                    }
                }
                return Boolean.valueOf(zE);
            case EventType.AUDIO /* 23 */:
                return new androidx.compose.animation.core.P(i3, (InterfaceC0773a0) obj2, (androidx.compose.foundation.interaction.l) obj3);
            case EventType.VIDEO /* 24 */:
                androidx.compose.ui.graphics.S s3 = (androidx.compose.ui.graphics.S) obj;
                N0 n0 = (N0) obj2;
                n0.getClass();
                if (!((Boolean) new C0513p(n0, i5).invoke()).booleanValue() || (h = (androidx.compose.ui.text.H) ((L0) n0.b).getValue()) == null || (c0985eC = N0.c((C0985e) obj3, h)) == null) {
                    c0850jK = null;
                } else {
                    int i13 = c0985eC.b;
                    int i14 = c0985eC.c;
                    c0850jK = h.k(i13, i14);
                    androidx.compose.ui.geometry.c cVarB = h.b(i13);
                    int i15 = i14 - 1;
                    androidx.compose.ui.geometry.c cVarB2 = h.b(i15);
                    if (h.f(i13) == h.f(i15)) {
                        fC = Math.min(cVarB2.a, cVarB.a);
                    }
                    c0850jK.g(Q4.c(fC, cVarB.b) ^ (-9223372034707292160L));
                }
                com.google.firebase.platforminfo.c cVar = c0850jK != null ? new com.google.firebase.platforminfo.c(c0850jK) : null;
                if (cVar != null) {
                    s3.t(cVar);
                    s3.e(true);
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                androidx.compose.ui.layout.V v3 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList2 = (ArrayList) obj2;
                if (arrayList2 != null) {
                    int size3 = arrayList2.size();
                    for (int i16 = 0; i16 < size3; i16++) {
                        Pair pair2 = (Pair) arrayList2.get(i16);
                        androidx.compose.ui.layout.V.e(v3, (androidx.compose.ui.layout.W) pair2.a, ((androidx.compose.ui.unit.h) pair2.b).a);
                    }
                }
                ArrayList arrayList3 = (ArrayList) obj3;
                if (arrayList3 != null) {
                    int size4 = arrayList3.size();
                    for (int i17 = 0; i17 < size4; i17++) {
                        Pair pair3 = (Pair) arrayList3.get(i17);
                        androidx.compose.ui.layout.W w3 = (androidx.compose.ui.layout.W) pair3.a;
                        Function0 function02 = (Function0) pair3.b;
                        androidx.compose.ui.layout.V.e(v3, w3, function02 != null ? ((androidx.compose.ui.unit.h) function02.invoke()).a : 0L);
                    }
                }
                return Unit.a;
            case EventType.CDN /* 26 */:
                MatchResult matchResult = (MatchResult) obj;
                kotlin.jvm.internal.H h3 = (kotlin.jvm.internal.H) obj2;
                if (h3.a == -1) {
                    h3.a = matchResult.c().a;
                }
                ((kotlin.jvm.internal.H) obj3).a = matchResult.c().b + 1;
                return "";
            case 27:
                androidx.compose.ui.input.pointer.n nVar = (androidx.compose.ui.input.pointer.n) obj;
                if (((InterfaceC0530k) obj2).c(nVar.c, (androidx.compose.foundation.text.selection.r) obj3)) {
                    nVar.a();
                }
                return Unit.a;
            case 28:
                C0536q c0536q = (C0536q) obj;
                ((androidx.compose.foundation.text.selection.U) obj2).m(c0536q);
                ((Function1) obj3).invoke(c0536q);
                return Unit.a;
            default:
                androidx.compose.foundation.contextmenu.j jVar = (androidx.compose.foundation.contextmenu.j) obj;
                androidx.compose.foundation.text.selection.U u = (androidx.compose.foundation.text.selection.U) obj3;
                androidx.compose.foundation.contextmenu.o oVar = (androidx.compose.foundation.contextmenu.o) obj2;
                androidx.compose.foundation.contextmenu.j.b(jVar, new C0547v(i5, i6), u.h(), new androidx.compose.foundation.text.selection.X(oVar, u, i6));
                Unit unit = Unit.a;
                androidx.compose.foundation.contextmenu.j.b(jVar, new C0547v(i4, i6), !u.f(), new androidx.compose.foundation.text.selection.X(oVar, u, i7));
                kotlin.collections.B.j(unit, unit);
                return unit;
        }
    }
}
