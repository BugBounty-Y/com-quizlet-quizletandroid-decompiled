package androidx.compose.ui.input.pointer;

import java.util.ArrayList;
import kotlin.collections.K;

/* loaded from: classes.dex */
public final class n {
    public final long a;
    public final long b;
    public final long c;
    public final boolean d;
    public final float e;
    public final long f;
    public final long g;
    public final boolean h;
    public final int i;
    public final long j;
    public final ArrayList k;
    public final long l;
    public androidx.camera.camera2.internal.compat.workaround.a m;

    public n(long j, long j2, long j3, boolean z, float f, long j4, long j5, boolean z2, boolean z3, int i, long j6) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = z;
        this.e = f;
        this.f = j4;
        this.g = j5;
        this.h = z2;
        this.i = i;
        this.j = j6;
        this.l = 0L;
        androidx.camera.camera2.internal.compat.workaround.a aVar = new androidx.camera.camera2.internal.compat.workaround.a();
        aVar.a = z3;
        aVar.b = z3;
        this.m = aVar;
    }

    public final void a() {
        androidx.camera.camera2.internal.compat.workaround.a aVar = this.m;
        aVar.b = true;
        aVar.a = true;
    }

    public final boolean b() {
        androidx.camera.camera2.internal.compat.workaround.a aVar = this.m;
        return aVar.b || aVar.a;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PointerInputChange(id=");
        sb.append((Object) m.b(this.a));
        sb.append(", uptimeMillis=");
        sb.append(this.b);
        sb.append(", position=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.c));
        sb.append(", pressed=");
        sb.append(this.d);
        sb.append(", pressure=");
        sb.append(this.e);
        sb.append(", previousUptimeMillis=");
        sb.append(this.f);
        sb.append(", previousPosition=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.g));
        sb.append(", previousPressed=");
        sb.append(this.h);
        sb.append(", isConsumed=");
        sb.append(b());
        sb.append(", type=");
        int i = this.i;
        sb.append((Object) (i != 1 ? i != 2 ? i != 3 ? i != 4 ? "Unknown" : "Eraser" : "Stylus" : "Mouse" : "Touch"));
        sb.append(", historical=");
        Object obj = this.k;
        if (obj == null) {
            obj = K.a;
        }
        sb.append(obj);
        sb.append(",scrollDelta=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.j));
        sb.append(')');
        return sb.toString();
    }

    public n(long j, long j2, long j3, boolean z, float f, long j4, long j5, boolean z2, int i, ArrayList arrayList, long j6, long j7) {
        this(j, j2, j3, z, f, j4, j5, z2, false, i, j6);
        this.k = arrayList;
        this.l = j7;
    }
}
