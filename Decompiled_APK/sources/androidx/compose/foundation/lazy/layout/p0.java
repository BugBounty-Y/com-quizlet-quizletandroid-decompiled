package androidx.compose.foundation.lazy.layout;

import android.os.Bundle;
import androidx.compose.foundation.text.selection.C0540v;
import androidx.compose.foundation.text.selection.InterfaceC0530k;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.InterfaceC2122h0;
import com.google.android.gms.internal.ads.S1;
import com.google.android.gms.internal.ads.Yo;
import com.google.android.gms.internal.ads.ZF;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.O0;
import com.google.android.gms.measurement.internal.f1;
import com.google.android.gms.measurement.internal.g1;
import com.google.android.gms.measurement.internal.x1;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.G1;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p0 implements InterfaceC0530k, S1, io.reactivex.rxjava3.functions.h {
    public long a;
    public long b;
    public Object c;
    public Object d;

    public p0(String str, byte[] bArr, long j, long j2) {
        this.c = str;
        this.d = bArr;
        this.a = j;
        this.b = j2;
    }

    public static final long d(p0 p0Var, long j, long j2) {
        p0Var.getClass();
        if (j2 == 0) {
            return j;
        }
        long j3 = 4;
        return (j / j3) + ((j2 / j3) * 3);
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0530k
    public boolean a(long j, androidx.compose.foundation.text.selection.r rVar) {
        androidx.compose.ui.layout.r rVar2 = (androidx.compose.ui.layout.r) ((androidx.compose.foundation.text.modifiers.g) this.c).invoke();
        if (rVar2 == null || !rVar2.k()) {
            return false;
        }
        androidx.compose.foundation.text.selection.b0 b0Var = (androidx.compose.foundation.text.selection.b0) ((androidx.compose.foundation.text.selection.Z) this.d);
        androidx.compose.foundation.lazy.f fVar = b0Var.f;
        if (fVar != null) {
            fVar.invoke(Boolean.FALSE, rVar2, new androidx.compose.ui.geometry.b(j), rVar);
        }
        this.a = j;
        return androidx.compose.foundation.text.selection.c0.a(b0Var, this.b);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Pair pair = (Pair) obj;
        Intrinsics.checkNotNullParameter(pair, "<destruct>");
        Object obj2 = pair.a;
        Intrinsics.checkNotNullExpressionValue(obj2, "component1(...)");
        Object obj3 = pair.b;
        Intrinsics.checkNotNullExpressionValue(obj3, "component2(...)");
        com.quizlet.features.infra.studysetting.managers.a aVar = (com.quizlet.features.infra.studysetting.managers.a) ((com.quizlet.data.repository.studysetwithcreatorinclass.g) this.c).d;
        long j = this.a;
        ArrayList arrayListJ = CollectionsKt.J((List) obj2);
        aVar.j(j, (G1) this.d, arrayListJ, (C1) obj3);
        return aVar;
    }

    @Override // com.google.android.gms.internal.ads.S1
    public void b(long j) {
        long[] jArr = (long[]) ((Fi) this.d).b;
        this.b = jArr[Yo.k(jArr, j, true)];
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0530k
    public boolean c(long j, androidx.compose.foundation.text.selection.r rVar) {
        androidx.compose.ui.layout.r rVar2 = (androidx.compose.ui.layout.r) ((androidx.compose.foundation.text.modifiers.g) this.c).invoke();
        if (rVar2 == null) {
            return true;
        }
        if (!rVar2.k()) {
            return false;
        }
        androidx.compose.foundation.text.selection.Z z = (androidx.compose.foundation.text.selection.Z) this.d;
        if (!androidx.compose.foundation.text.selection.c0.a(z, this.b)) {
            return false;
        }
        if (!((androidx.compose.foundation.text.selection.b0) z).b(rVar2, j, this.a, rVar, false)) {
            return true;
        }
        this.a = j;
        return true;
    }

    public void e(Object obj, Object obj2, coil3.memory.d dVar) {
        coil3.memory.d dVar2 = (coil3.memory.d) obj2;
        ((com.android.billingclient.api.s) ((androidx.work.impl.model.v) this.d).b).m((coil3.memory.a) obj, dVar2.a, dVar2.b, dVar2.c);
    }

    public long f() {
        if (this.b == -1) {
            long jG = 0;
            for (Map.Entry entry : ((LinkedHashMap) this.c).entrySet()) {
                jG += g(entry.getKey(), entry.getValue());
            }
            this.b = jG;
        }
        return this.b;
    }

    public long g(Object obj, Object obj2) throws Exception {
        try {
            long j = ((coil3.memory.d) obj2).c;
            if (j >= 0) {
                return j;
            }
            throw new IllegalStateException(("sizeOf(" + obj + ", " + obj2 + ") returned a negative value: " + j).toString());
        } catch (Exception e) {
            this.b = -1L;
            throw e;
        }
    }

    public void h(long j) {
        while (f() > j) {
            LinkedHashMap linkedHashMap = (LinkedHashMap) this.c;
            if (linkedHashMap.isEmpty()) {
                if (f() != 0) {
                    throw new IllegalStateException("sizeOf() is returning inconsistent values");
                }
                return;
            }
            Map.Entry entry = (Map.Entry) CollectionsKt.K(linkedHashMap.entrySet());
            Object key = entry.getKey();
            Object value = entry.getValue();
            linkedHashMap.remove(key);
            this.b = f() - g(key, value);
            e(key, value, null);
        }
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0530k
    public void i() {
        C0540v c0540v = ((androidx.compose.foundation.text.selection.b0) ((androidx.compose.foundation.text.selection.Z) this.d)).h;
        if (c0540v != null) {
            c0540v.invoke();
        }
    }

    @Override // com.google.android.gms.internal.ads.S1
    public long j(com.google.android.gms.internal.ads.P p) {
        long j = this.b;
        if (j < 0) {
            return -1L;
        }
        this.b = -1L;
        return -(j + 2);
    }

    public boolean k(long j, boolean z, boolean z2) {
        g1 g1Var = (g1) this.d;
        g1Var.S();
        g1Var.Q();
        com.google.android.gms.measurement.internal.Y y = (com.google.android.gms.measurement.internal.Y) g1Var.b;
        if (y.a()) {
            com.google.android.gms.measurement.internal.O o = y.h;
            com.google.android.gms.measurement.internal.Y.h(o);
            y.n.getClass();
            o.r.b(System.currentTimeMillis());
        }
        long j2 = j - this.a;
        com.google.android.gms.measurement.internal.I i = y.i;
        if (!z && j2 < 1000) {
            com.google.android.gms.measurement.internal.Y.k(i);
            i.o.g("Screen exposed for less than 1000 ms. Event not sent. time", Long.valueOf(j2));
            return false;
        }
        if (!z2) {
            j2 = j - this.b;
            this.b = j;
        }
        com.google.android.gms.measurement.internal.Y.k(i);
        i.o.g("Recording user engagement, ms", Long.valueOf(j2));
        Bundle bundle = new Bundle();
        bundle.putLong("_et", j2);
        boolean z3 = !y.g.g0();
        O0 o0 = y.o;
        com.google.android.gms.measurement.internal.Y.j(o0);
        x1.h0(o0.Y(z3), bundle, true);
        if (!z2) {
            D0 d0 = y.p;
            com.google.android.gms.measurement.internal.Y.j(d0);
            d0.c0("auto", "_e", bundle);
        }
        this.a = j;
        f1 f1Var = (f1) this.c;
        f1Var.a();
        f1Var.c(((Long) AbstractC3893t.p0.a(null)).longValue());
        return true;
    }

    @Override // com.google.android.gms.internal.ads.S1
    public InterfaceC2122h0 zze() {
        AbstractC1795We.L(this.a != -1);
        return new com.google.android.gms.internal.ads.Y((com.google.android.gms.internal.ads.Z) this.c, this.a, 0);
    }

    public p0(long j) {
        AbstractC1795We.L(((ZF) this.c) == null);
        this.a = j;
        this.b = j + 65536;
    }
}
