package androidx.compose.ui.graphics.vector;

import android.graphics.Path;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.C0851k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.graphics.vector.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0870i extends D {
    public AbstractC0857q b;
    public float f;
    public AbstractC0857q g;
    public float k;
    public float m;
    public boolean p;
    public androidx.compose.ui.graphics.drawscope.h q;
    public final C0850j r;
    public C0850j s;
    public final Object t;
    public float c = 1.0f;
    public Object d = I.a;
    public float e = 1.0f;
    public int h = 0;
    public int i = 0;
    public float j = 4.0f;
    public float l = 1.0f;
    public boolean n = true;
    public boolean o = true;

    public C0870i() {
        C0850j c0850jH = androidx.compose.ui.graphics.F.h();
        this.r = c0850jH;
        this.s = c0850jH;
        this.t = kotlin.l.a(kotlin.m.c, C0869h.b);
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.ui.graphics.vector.D
    public final void a(androidx.compose.ui.graphics.drawscope.d dVar) {
        androidx.compose.ui.graphics.drawscope.d dVar2;
        androidx.compose.ui.graphics.drawscope.h hVar;
        if (this.n) {
            AbstractC0863b.d(this.d, this.r);
            e();
        } else if (this.p) {
            e();
        }
        this.n = false;
        this.p = false;
        AbstractC0857q abstractC0857q = this.b;
        if (abstractC0857q != null) {
            dVar2 = dVar;
            androidx.compose.ui.graphics.drawscope.d.A(dVar2, this.s, abstractC0857q, this.c, null, 56);
        } else {
            dVar2 = dVar;
        }
        AbstractC0857q abstractC0857q2 = this.g;
        if (abstractC0857q2 != null) {
            androidx.compose.ui.graphics.drawscope.h hVar2 = this.q;
            if (this.o || hVar2 == null) {
                androidx.compose.ui.graphics.drawscope.h hVar3 = new androidx.compose.ui.graphics.drawscope.h(this.f, this.j, this.h, this.i, 16);
                this.q = hVar3;
                this.o = false;
                hVar = hVar3;
            } else {
                hVar = hVar2;
            }
            androidx.compose.ui.graphics.drawscope.d.A(dVar2, this.s, abstractC0857q2, this.e, hVar, 48);
        }
    }

    /* JADX WARN: Type inference failed for: r0v10, types: [java.lang.Object, kotlin.k] */
    public final void e() {
        Path path;
        float f = this.k;
        C0850j c0850j = this.r;
        if (f == DefinitionKt.NO_Float_VALUE && this.l == 1.0f) {
            this.s = c0850j;
            return;
        }
        if (Intrinsics.b(this.s, c0850j)) {
            this.s = androidx.compose.ui.graphics.F.h();
        } else {
            int i = this.s.a.getFillType() == Path.FillType.EVEN_ODD ? 1 : 0;
            this.s.a.rewind();
            this.s.f(i);
        }
        ?? r0 = this.t;
        C0851k c0851k = (C0851k) r0.getValue();
        if (c0850j != null) {
            c0851k.getClass();
            path = c0850j.a;
        } else {
            path = null;
        }
        c0851k.a.setPath(path, false);
        float length = ((C0851k) r0.getValue()).a.getLength();
        float f2 = this.k;
        float f3 = this.m;
        float f4 = ((f2 + f3) % 1.0f) * length;
        float f5 = ((this.l + f3) % 1.0f) * length;
        if (f4 <= f5) {
            ((C0851k) r0.getValue()).a(f4, f5, this.s);
        } else {
            ((C0851k) r0.getValue()).a(f4, length, this.s);
            ((C0851k) r0.getValue()).a(DefinitionKt.NO_Float_VALUE, f5, this.s);
        }
    }

    public final String toString() {
        return this.r.toString();
    }
}
