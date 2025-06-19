package com.airbnb.lottie.compose;

import androidx.compose.foundation.y0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.E;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.W0;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class h implements W0 {
    public final InterfaceC0773a0 a;
    public final InterfaceC0773a0 b;
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;
    public final InterfaceC0773a0 f;
    public final InterfaceC0773a0 g;
    public final E h;
    public final InterfaceC0773a0 i;
    public final InterfaceC0773a0 j;
    public final InterfaceC0773a0 k;
    public final InterfaceC0773a0 l;
    public final E m;
    public final y0 n;

    public h() {
        Boolean bool = Boolean.FALSE;
        this.a = C0776c.z(bool);
        this.b = C0776c.z(1);
        this.c = C0776c.z(1);
        this.d = C0776c.z(bool);
        this.e = C0776c.z(null);
        this.f = C0776c.z(Float.valueOf(1.0f));
        this.g = C0776c.z(bool);
        this.h = C0776c.q(new f(this, 1));
        this.i = C0776c.z(null);
        Float fValueOf = Float.valueOf(DefinitionKt.NO_Float_VALUE);
        this.j = C0776c.z(fValueOf);
        this.k = C0776c.z(fValueOf);
        this.l = C0776c.z(Long.MIN_VALUE);
        this.m = C0776c.q(new f(this, 0));
        C0776c.q(new f(this, 2));
        this.n = new y0();
    }

    public static final boolean a(h hVar, int i, long j) {
        com.airbnb.lottie.h hVar2 = (com.airbnb.lottie.h) ((L0) hVar.i).getValue();
        if (hVar2 == null) {
            return true;
        }
        InterfaceC0773a0 interfaceC0773a0 = hVar.l;
        long jLongValue = ((Number) ((L0) interfaceC0773a0).getValue()).longValue() == Long.MIN_VALUE ? 0L : j - ((Number) ((L0) interfaceC0773a0).getValue()).longValue();
        ((L0) interfaceC0773a0).setValue(Long.valueOf(j));
        InterfaceC0773a0 interfaceC0773a02 = hVar.e;
        if (((L0) interfaceC0773a02).getValue() != null) {
            throw new ClassCastException();
        }
        if (((L0) interfaceC0773a02).getValue() != null) {
            throw new ClassCastException();
        }
        float fB = (jLongValue / 1000000) / hVar2.b();
        E e = hVar.h;
        float fFloatValue = ((Number) e.getValue()).floatValue() * fB;
        float fFloatValue2 = ((Number) e.getValue()).floatValue();
        InterfaceC0773a0 interfaceC0773a03 = hVar.j;
        float fFloatValue3 = fFloatValue2 < DefinitionKt.NO_Float_VALUE ? DefinitionKt.NO_Float_VALUE - (((Number) ((L0) interfaceC0773a03).getValue()).floatValue() + fFloatValue) : (((Number) ((L0) interfaceC0773a03).getValue()).floatValue() + fFloatValue) - 1.0f;
        if (fFloatValue3 < DefinitionKt.NO_Float_VALUE) {
            hVar.h(kotlin.ranges.l.b(((Number) ((L0) interfaceC0773a03).getValue()).floatValue(), DefinitionKt.NO_Float_VALUE, 1.0f) + fFloatValue);
            return true;
        }
        int i2 = (int) (fFloatValue3 / 1.0f);
        int i3 = i2 + 1;
        if (hVar.f() + i3 > i) {
            hVar.h(hVar.e());
            hVar.g(i);
            return false;
        }
        hVar.g(hVar.f() + i3);
        float f = fFloatValue3 - (i2 * 1.0f);
        hVar.h(((Number) e.getValue()).floatValue() < DefinitionKt.NO_Float_VALUE ? 1.0f - f : DefinitionKt.NO_Float_VALUE + f);
        return true;
    }

    public static final void b(h hVar, boolean z) {
        ((L0) hVar.a).setValue(Boolean.valueOf(z));
    }

    public final float e() {
        return ((Number) this.m.getValue()).floatValue();
    }

    public final int f() {
        return ((Number) ((L0) this.b).getValue()).intValue();
    }

    public final void g(int i) {
        ((L0) this.b).setValue(Integer.valueOf(i));
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return Float.valueOf(((Number) ((L0) this.k).getValue()).floatValue());
    }

    public final void h(float f) {
        com.airbnb.lottie.h hVar;
        ((L0) this.j).setValue(Float.valueOf(f));
        if (((Boolean) ((L0) this.g).getValue()).booleanValue() && (hVar = (com.airbnb.lottie.h) ((L0) this.i).getValue()) != null) {
            f -= f % (1 / hVar.n);
        }
        ((L0) this.k).setValue(Float.valueOf(f));
    }
}
