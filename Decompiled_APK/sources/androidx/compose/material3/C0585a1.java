package androidx.compose.material3;

import androidx.compose.material3.internal.C0654s;
import androidx.compose.material3.internal.C0656u;
import androidx.compose.material3.internal.C0657v;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import java.time.LocalDate;
import java.util.Locale;
import kotlin.ranges.IntRange;

/* renamed from: androidx.compose.material3.a1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0585a1 {
    public final IntRange a;
    public final C0656u b;
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;
    public final InterfaceC0773a0 f;

    public C0585a1(Long l, Long l2, IntRange intRange, int i, InterfaceC0764y3 interfaceC0764y3, Locale locale) {
        C0657v c0657vD;
        C0654s c0654sC;
        this.a = intRange;
        C0656u c0656u = new C0656u(locale);
        this.b = c0656u;
        this.c = C0776c.z(interfaceC0764y3);
        if (l2 != null) {
            c0657vD = c0656u.a(l2.longValue());
            int i2 = c0657vD.a;
            if (!intRange.b(i2)) {
                throw new IllegalArgumentException(("The initial display month's year (" + i2 + ") is out of the years range of " + intRange + '.').toString());
            }
        } else {
            C0654s c0654sB = c0656u.b();
            c0657vD = c0656u.d(LocalDate.of(c0654sB.a, c0654sB.b, 1));
        }
        this.d = C0776c.z(c0657vD);
        if (l != null) {
            c0654sC = this.b.c(l.longValue());
            int i3 = c0654sC.a;
            if (!intRange.b(i3)) {
                throw new IllegalArgumentException(("The provided initial date's year (" + i3 + ") is out of the years range of " + intRange + '.').toString());
            }
        } else {
            c0654sC = null;
        }
        this.e = C0776c.z(c0654sC);
        this.f = C0776c.z(new C0615f1(i));
    }

    public final int a() {
        return ((C0615f1) ((androidx.compose.runtime.L0) this.f).getValue()).a;
    }

    public final Long b() {
        C0654s c0654s = (C0654s) ((androidx.compose.runtime.L0) this.e).getValue();
        if (c0654s != null) {
            return Long.valueOf(c0654s.d);
        }
        return null;
    }

    public final void c(long j) {
        C0657v c0657vA = this.b.a(j);
        IntRange intRange = this.a;
        int i = c0657vA.a;
        if (intRange.b(i)) {
            ((androidx.compose.runtime.L0) this.d).setValue(c0657vA);
            return;
        }
        throw new IllegalArgumentException(("The display month's year (" + i + ") is out of the years range of " + intRange + '.').toString());
    }
}
