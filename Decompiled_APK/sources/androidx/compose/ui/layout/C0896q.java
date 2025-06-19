package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.Map;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.layout.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0896q implements M, InterfaceC0894o {
    public final androidx.compose.ui.unit.k a;
    public final /* synthetic */ InterfaceC0894o b;

    public C0896q(InterfaceC0894o interfaceC0894o, androidx.compose.ui.unit.k kVar) {
        this.a = kVar;
        this.b = interfaceC0894o;
    }

    @Override // androidx.compose.ui.unit.b
    public final long K(float f) {
        return this.b.K(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float O(int i) {
        return this.b.O(i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float R(float f) {
        return this.b.R(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.b.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.b.a();
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final boolean a0() {
        return this.b.a0();
    }

    @Override // androidx.compose.ui.unit.b
    public final float c0(float f) {
        return this.b.c0(f);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.a;
    }

    @Override // androidx.compose.ui.unit.b
    public final int j0(long j) {
        return this.b.j0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final int m0(float f) {
        return this.b.m0(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long q0(long j) {
        return this.b.q0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return this.b.r(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long s(long j) {
        return this.b.s(j);
    }

    @Override // androidx.compose.ui.layout.M
    public final L v(int i, int i2, Map map, Function1 function1) {
        if (i < 0) {
            i = 0;
        }
        if (i2 < 0) {
            i2 = 0;
        }
        if ((i & (-16777216)) == 0 && ((-16777216) & i2) == 0) {
            return new C0895p(i, i2, map);
        }
        W4.f("Size(" + i + " x " + i2 + ") is out of range. Each dimension must be between 0 and 16777215.");
        throw null;
    }

    @Override // androidx.compose.ui.unit.b
    public final float v0(long j) {
        return this.b.v0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        return this.b.y(j);
    }
}
