package androidx.glance.color;

import androidx.compose.ui.node.B;
import androidx.glance.unit.i;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public static final b B = new b(new i(R.color.glance_colorPrimary), new i(R.color.glance_colorOnPrimary), new i(R.color.glance_colorPrimaryContainer), new i(R.color.glance_colorOnPrimaryContainer), new i(R.color.glance_colorSecondary), new i(R.color.glance_colorOnSecondary), new i(R.color.glance_colorSecondaryContainer), new i(R.color.glance_colorOnSecondaryContainer), new i(R.color.glance_colorTertiary), new i(R.color.glance_colorOnTertiary), new i(R.color.glance_colorTertiaryContainer), new i(R.color.glance_colorOnTertiaryContainer), new i(R.color.glance_colorError), new i(R.color.glance_colorErrorContainer), new i(R.color.glance_colorOnError), new i(R.color.glance_colorOnErrorContainer), new i(R.color.glance_colorBackground), new i(R.color.glance_colorOnBackground), new i(R.color.glance_colorSurface), new i(R.color.glance_colorOnSurface), new i(R.color.glance_colorSurfaceVariant), new i(R.color.glance_colorOnSurfaceVariant), new i(R.color.glance_colorOutline), new i(R.color.glance_colorOnSurfaceInverse), new i(R.color.glance_colorSurfaceInverse), new i(R.color.glance_colorPrimaryInverse), new i(R.color.glance_colorWidgetBackground));
    public final i A;
    public final i a;
    public final i b;
    public final i c;
    public final i d;
    public final i e;
    public final i f;
    public final i g;
    public final i h;
    public final i i;
    public final i j;
    public final i k;
    public final i l;
    public final i m;
    public final i n;
    public final i o;
    public final i p;
    public final i q;
    public final i r;
    public final i s;
    public final i t;
    public final i u;
    public final i v;
    public final i w;
    public final i x;
    public final i y;
    public final i z;

    public b(i iVar, i iVar2, i iVar3, i iVar4, i iVar5, i iVar6, i iVar7, i iVar8, i iVar9, i iVar10, i iVar11, i iVar12, i iVar13, i iVar14, i iVar15, i iVar16, i iVar17, i iVar18, i iVar19, i iVar20, i iVar21, i iVar22, i iVar23, i iVar24, i iVar25, i iVar26, i iVar27) {
        this.a = iVar;
        this.b = iVar2;
        this.c = iVar3;
        this.d = iVar4;
        this.e = iVar5;
        this.f = iVar6;
        this.g = iVar7;
        this.h = iVar8;
        this.i = iVar9;
        this.j = iVar10;
        this.k = iVar11;
        this.l = iVar12;
        this.m = iVar13;
        this.n = iVar14;
        this.o = iVar15;
        this.p = iVar16;
        this.q = iVar17;
        this.r = iVar18;
        this.s = iVar19;
        this.t = iVar20;
        this.u = iVar21;
        this.v = iVar22;
        this.w = iVar23;
        this.x = iVar24;
        this.y = iVar25;
        this.z = iVar26;
        this.A = iVar27;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!getClass().equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.glance.color.ColorProviders");
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b.equals(bVar.b) && this.c.equals(bVar.c) && this.d.equals(bVar.d) && this.e.equals(bVar.e) && this.f.equals(bVar.f) && this.g.equals(bVar.g) && this.h.equals(bVar.h) && this.i.equals(bVar.i) && this.j.equals(bVar.j) && this.k.equals(bVar.k) && this.l.equals(bVar.l) && this.m.equals(bVar.m) && this.n.equals(bVar.n) && this.o.equals(bVar.o) && this.p.equals(bVar.p) && this.q.equals(bVar.q) && this.r.equals(bVar.r) && this.s.equals(bVar.s) && this.t.equals(bVar.t) && this.u.equals(bVar.u) && this.v.equals(bVar.v) && this.w.equals(bVar.w) && this.x.equals(bVar.x) && this.y.equals(bVar.y) && this.z.equals(bVar.z) && this.A.equals(bVar.A);
    }

    public final int hashCode() {
        return this.A.hashCode() + B.a(this.z, B.a(this.y, B.a(this.x, B.a(this.w, B.a(this.v, B.a(this.u, B.a(this.t, B.a(this.s, B.a(this.r, B.a(this.q, B.a(this.p, B.a(this.o, B.a(this.n, B.a(this.m, B.a(this.l, B.a(this.k, B.a(this.j, B.a(this.i, B.a(this.h, B.a(this.g, B.a(this.f, B.a(this.e, B.a(this.d, B.a(this.c, B.a(this.b, this.a.hashCode() * 31, 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31), 31);
    }

    public final String toString() {
        return "ColorProviders(primary=" + this.a + ", onPrimary=" + this.b + ", primaryContainer=" + this.c + ", onPrimaryContainer=" + this.d + ", secondary=" + this.e + ", onSecondary=" + this.f + ", secondaryContainer=" + this.g + ", onSecondaryContainer=" + this.h + ", tertiary=" + this.i + ", onTertiary=" + this.j + ", tertiaryContainer=" + this.k + ", onTertiaryContainer=" + this.l + ", error=" + this.m + ", errorContainer=" + this.n + ", onError=" + this.o + ", onErrorContainer=" + this.p + ", background=" + this.q + ", onBackground=" + this.r + ", surface=" + this.s + ", onSurface=" + this.t + ", surfaceVariant=" + this.u + ", onSurfaceVariant=" + this.v + ", outline=" + this.w + ", inverseOnSurface=" + this.x + ", inverseSurface=" + this.y + ", inversePrimary=" + this.z + ")widgetBackground=" + this.A;
    }
}
