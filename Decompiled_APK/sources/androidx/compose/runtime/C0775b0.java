package androidx.compose.runtime;

import androidx.compose.animation.C0281h;
import androidx.compose.ui.draw.ShadowGraphicsLayerElement;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.vector.C0864c;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.node.InterfaceC0905a;
import androidx.compose.ui.platform.AbstractC0968t0;
import androidx.compose.ui.platform.C0961p0;
import androidx.compose.ui.platform.C0970u0;
import androidx.compose.ui.platform.C0974w0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentContainerView;
import com.comscore.streaming.EventType;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: androidx.compose.runtime.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0775b0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0775b0(Object obj, int i) {
        super(1);
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r0v36, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v37, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v43, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v55, types: [androidx.compose.ui.layout.W, androidx.compose.ui.node.a] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 0;
        Object objInvoke = null;
        switch (this.a) {
            case 0:
                return Boolean.valueOf(Intrinsics.b(((C0777c0) obj).b, (Z) this.b));
            case 1:
                Throwable th = (Throwable) obj;
                CancellationException cancellationExceptionA = kotlinx.coroutines.E.a("Recomposer effect job completed", th);
                C0832v0 c0832v0 = (C0832v0) this.b;
                synchronized (c0832v0.c) {
                    try {
                        InterfaceC5025j0 interfaceC5025j0 = c0832v0.d;
                        if (interfaceC5025j0 != null) {
                            kotlinx.coroutines.flow.s0 s0Var = c0832v0.u;
                            EnumC0817q0 enumC0817q0 = EnumC0817q0.b;
                            s0Var.getClass();
                            s0Var.m(null, enumC0817q0);
                            kotlinx.coroutines.flow.s0 s0Var2 = C0832v0.y;
                            interfaceC5025j0.j(cancellationExceptionA);
                            c0832v0.r = null;
                            interfaceC5025j0.Q(new androidx.compose.foundation.text.selection.n0(13, c0832v0, th));
                        } else {
                            c0832v0.e = cancellationExceptionA;
                            kotlinx.coroutines.flow.s0 s0Var3 = c0832v0.u;
                            EnumC0817q0 enumC0817q02 = EnumC0817q0.a;
                            s0Var3.getClass();
                            s0Var3.m(null, enumC0817q02);
                            Unit unit = Unit.a;
                        }
                    } catch (Throwable th2) {
                        throw th2;
                    }
                }
                return Unit.a;
            case 2:
                ((C0833w) this.b).c(obj);
                return Unit.a;
            case 3:
                ((F0) this.b).j(((Number) obj).floatValue());
                return Unit.a;
            case 4:
                ((J0) this.b).j(((Number) obj).longValue());
                return Unit.a;
            case 5:
                ((L0) this.b).setValue(obj);
                return Unit.a;
            case 6:
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) obj;
                if (!(interfaceC0773a0 instanceof androidx.compose.runtime.snapshots.o)) {
                    throw new IllegalArgumentException("Failed requirement.");
                }
                if (interfaceC0773a0.getValue() != null) {
                    Object value = interfaceC0773a0.getValue();
                    Intrinsics.d(value);
                    objInvoke = ((Function1) ((com.quizlet.data.repository.explanations.myexplanations.a) this.b).c).invoke(value);
                }
                M0 m0D = ((androidx.compose.runtime.snapshots.o) interfaceC0773a0).d();
                Intrinsics.e(m0D, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutationPolicy<T of androidx.compose.runtime.saveable.RememberSaveableKt.mutableStateSaver?>");
                return C0776c.y(objInvoke, m0D);
            case 7:
                androidx.compose.runtime.saveable.i iVar = ((androidx.compose.runtime.saveable.f) this.b).c;
                return Boolean.valueOf(iVar != null ? iVar.a(obj) : true);
            case 8:
                androidx.compose.runtime.snapshots.v vVar = (androidx.compose.runtime.snapshots.v) this.b;
                vVar.getClass();
                synchronized (vVar.g) {
                    androidx.compose.runtime.snapshots.u uVar = vVar.i;
                    Intrinsics.d(uVar);
                    Object obj2 = uVar.b;
                    Intrinsics.d(obj2);
                    int i2 = uVar.d;
                    androidx.collection.C c = uVar.c;
                    if (c == null) {
                        c = new androidx.collection.C();
                        uVar.c = c;
                        uVar.f.j(obj2, c);
                        Unit unit2 = Unit.a;
                    }
                    uVar.c(obj, i2, obj2, c);
                }
                return Unit.a;
            case 9:
                androidx.compose.ui.node.G g = (androidx.compose.ui.node.G) obj;
                ((androidx.compose.foundation.text.selection.n0) this.b).invoke(g);
                g.b();
                return Unit.a;
            case 10:
                androidx.compose.ui.graphics.S s = (androidx.compose.ui.graphics.S) obj;
                ShadowGraphicsLayerElement shadowGraphicsLayerElement = (ShadowGraphicsLayerElement) this.b;
                s.p(s.a() * shadowGraphicsLayerElement.b);
                s.t(shadowGraphicsLayerElement.c);
                s.e(shadowGraphicsLayerElement.d);
                s.c(shadowGraphicsLayerElement.e);
                s.u(shadowGraphicsLayerElement.f);
                return Unit.a;
            case 11:
                androidx.compose.ui.graphics.S s2 = (androidx.compose.ui.graphics.S) obj;
                androidx.compose.ui.graphics.W w = (androidx.compose.ui.graphics.W) this.b;
                s2.m(w.n);
                s2.o(w.o);
                s2.b(w.p);
                s2.z(DefinitionKt.NO_Float_VALUE);
                s2.B(DefinitionKt.NO_Float_VALUE);
                s2.p(w.q);
                s2.h(DefinitionKt.NO_Float_VALUE);
                s2.i(DefinitionKt.NO_Float_VALUE);
                s2.k(w.r);
                s2.d(w.s);
                s2.x(w.t);
                s2.t(w.u);
                s2.e(w.v);
                s2.f(null);
                s2.c(w.w);
                s2.u(w.x);
                int i3 = w.y;
                if (s2.q != i3) {
                    s2.a |= 32768;
                    s2.q = i3;
                }
                return Unit.a;
            case 12:
                androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
                androidx.compose.ui.graphics.layer.b bVar = (androidx.compose.ui.graphics.layer.b) this.b;
                C0850j c0850j = bVar.l;
                if (bVar.n && bVar.v && c0850j != null) {
                    ?? r0 = bVar.d;
                    com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
                    long jR = cVarE0.r();
                    cVarE0.o().e();
                    try {
                        ((com.quizlet.data.repository.folderset.c) ((androidx.appcompat.app.L) cVarE0.b).b).o().i(c0850j);
                        r0.invoke(dVar);
                    } finally {
                        androidx.compose.animation.d0.y(cVarE0, jR);
                    }
                } else {
                    bVar.d.invoke(dVar);
                }
                return Unit.a;
            case 13:
                ((androidx.compose.ui.graphics.painter.b) this.b).i((androidx.compose.ui.graphics.drawscope.d) obj);
                return Unit.a;
            case 14:
                androidx.compose.ui.graphics.vector.D d = (androidx.compose.ui.graphics.vector.D) obj;
                C0864c c0864c = (C0864c) this.b;
                c0864c.g(d);
                ?? r02 = c0864c.i;
                if (r02 != 0) {
                    r02.invoke(d);
                }
                return Unit.a;
            case 15:
                Throwable th3 = (Throwable) obj;
                androidx.compose.ui.input.pointer.z zVar = (androidx.compose.ui.input.pointer.z) this.b;
                C5028l c5028l = zVar.c;
                if (c5028l != null) {
                    c5028l.b(th3);
                }
                zVar.c = null;
                return Unit.a;
            case 16:
                Map.Entry entry = (Map.Entry) obj;
                Object key = entry.getKey();
                androidx.compose.ui.layout.c0 c0Var = (androidx.compose.ui.layout.c0) entry.getValue();
                androidx.compose.ui.layout.G g2 = (androidx.compose.ui.layout.G) this.b;
                int iK = g2.m.k(key);
                if (iK < 0 || iK >= g2.e) {
                    c0Var.dispose();
                } else {
                    z = false;
                }
                return Boolean.valueOf(z);
            case 17:
                InterfaceC0905a interfaceC0905a = (InterfaceC0905a) obj;
                if (interfaceC0905a.M()) {
                    if (interfaceC0905a.c().b) {
                        interfaceC0905a.L();
                    }
                    Iterator it2 = interfaceC0905a.c().i.entrySet().iterator();
                    while (true) {
                        boolean zHasNext = it2.hasNext();
                        androidx.compose.ui.node.F f = (androidx.compose.ui.node.F) this.b;
                        if (zHasNext) {
                            Map.Entry entry2 = (Map.Entry) it2.next();
                            androidx.compose.ui.node.F.a(f, (C0893n) entry2.getKey(), ((Number) entry2.getValue()).intValue(), interfaceC0905a.e());
                        } else {
                            androidx.compose.ui.node.a0 a0Var = interfaceC0905a.e().n;
                            Intrinsics.d(a0Var);
                            while (!a0Var.equals(f.a.e())) {
                                for (C0893n c0893n : f.b(a0Var).keySet()) {
                                    androidx.compose.ui.node.F.a(f, c0893n, f.c(a0Var, c0893n), a0Var);
                                }
                                a0Var = a0Var.n;
                                Intrinsics.d(a0Var);
                            }
                        }
                    }
                }
                return Unit.a;
            case 18:
                return new androidx.activity.compose.c((C0961p0) this.b, 9);
            case 19:
                if (AbstractC0968t0.b.compareAndSet(false, true)) {
                    ((kotlinx.coroutines.channels.h) this.b).o(Unit.a);
                }
                return Unit.a;
            case 20:
                androidx.compose.ui.graphics.drawscope.d dVar2 = (androidx.compose.ui.graphics.drawscope.d) obj;
                InterfaceC0858s interfaceC0858sO = dVar2.e0().o();
                C0281h c0281h = ((C0970u0) this.b).d;
                if (c0281h != null) {
                    c0281h.invoke(interfaceC0858sO, (androidx.compose.ui.graphics.layer.b) dVar2.e0().c);
                }
                return Unit.a;
            case 21:
                androidx.compose.ui.text.input.p pVar = (androidx.compose.ui.text.input.p) obj;
                androidx.compose.foundation.text.input.internal.D d2 = pVar.b;
                if (d2 != null) {
                    pVar.a(d2);
                    pVar.b = null;
                }
                C0974w0 c0974w0 = (C0974w0) this.b;
                androidx.compose.runtime.collection.b bVar2 = c0974w0.d;
                int i4 = bVar2.c;
                if (i4 > 0) {
                    Object[] objArr = bVar2.a;
                    while (!Intrinsics.b((WeakReference) objArr[i], pVar)) {
                        i++;
                        if (i >= i4) {
                            i = -1;
                        }
                    }
                } else {
                    i = -1;
                }
                androidx.compose.runtime.collection.b bVar3 = c0974w0.d;
                if (i >= 0) {
                    bVar3.o(i);
                }
                if (bVar3.l()) {
                    c0974w0.b.invoke();
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                ((C0281h) this.b).invoke((InterfaceC0858s) obj, null);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                androidx.compose.ui.semantics.t.h((androidx.compose.ui.semantics.v) obj, ((androidx.compose.ui.semantics.h) this.b).a);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                ((List) obj).add((Float) ((androidx.compose.foundation.lazy.layout.f0) this.b).invoke());
                return true;
            case EventType.SUBS /* 25 */:
                androidx.compose.ui.text.font.E e = (androidx.compose.ui.text.font.E) obj;
                return ((androidx.compose.ui.text.font.k) this.b).a(new androidx.compose.ui.text.font.E(null, e.b, e.c, e.d, e.e)).getValue();
            case EventType.CDN /* 26 */:
                FragmentContainerView fragmentContainerView = (FragmentContainerView) obj;
                AbstractC1136h0 abstractC1136h0 = (AbstractC1136h0) this.b;
                Fragment fragmentD = abstractC1136h0 != null ? abstractC1136h0.D(fragmentContainerView.getId()) : null;
                if (fragmentD != null && !abstractC1136h0.R()) {
                    C1121a c1121a = new C1121a(abstractC1136h0);
                    Intrinsics.checkNotNullExpressionValue(c1121a, "beginTransaction()");
                    c1121a.k(fragmentD);
                    if (c1121a.g) {
                        throw new IllegalStateException("This transaction is already being added to the back stack");
                    }
                    c1121a.h = false;
                    c1121a.r.B(c1121a, false);
                }
                return Unit.a;
            case 27:
                ((androidx.compose.ui.node.E) this.b).W((androidx.compose.ui.unit.b) obj);
                return Unit.a;
            case 28:
                ((com.google.common.util.concurrent.e) this.b).cancel(false);
                return Unit.a;
            default:
                androidx.compose.ui.graphics.S s3 = (androidx.compose.ui.graphics.S) obj;
                androidx.constraintlayout.core.state.k kVar = (androidx.constraintlayout.core.state.k) this.b;
                if (!Float.isNaN(kVar.d) || !Float.isNaN(kVar.e)) {
                    s3.x(androidx.compose.ui.graphics.F.i(Float.isNaN(kVar.d) ? 0.5f : kVar.d, Float.isNaN(kVar.e) ? 0.5f : kVar.e));
                }
                if (!Float.isNaN(kVar.f)) {
                    s3.h(kVar.f);
                }
                if (!Float.isNaN(kVar.g)) {
                    s3.i(kVar.g);
                }
                if (!Float.isNaN(kVar.h)) {
                    s3.k(kVar.h);
                }
                if (!Float.isNaN(kVar.i)) {
                    s3.z(kVar.i);
                }
                if (!Float.isNaN(kVar.j)) {
                    s3.B(kVar.j);
                }
                if (!Float.isNaN(kVar.k)) {
                    s3.p(kVar.k);
                }
                if (!Float.isNaN(kVar.l) || !Float.isNaN(kVar.m)) {
                    s3.m(Float.isNaN(kVar.l) ? 1.0f : kVar.l);
                    s3.o(Float.isNaN(kVar.m) ? 1.0f : kVar.m);
                }
                if (!Float.isNaN(kVar.n)) {
                    s3.b(kVar.n);
                }
                return Unit.a;
        }
    }
}
