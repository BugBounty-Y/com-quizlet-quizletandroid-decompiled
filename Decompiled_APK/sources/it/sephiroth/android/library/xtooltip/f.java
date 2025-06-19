package it.sephiroth.android.library.xtooltip;

import android.graphics.Point;
import android.graphics.Rect;
import android.view.WindowManager;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final Rect g;
    public final Point h;
    public final Point i;
    public final Point j;
    public final e k;
    public final WindowManager.LayoutParams l;

    public f(Rect rect, Point point, Point point2, Point point3, e eVar, WindowManager.LayoutParams layoutParams) {
        this.g = rect;
        this.h = point;
        this.i = point2;
        this.j = point3;
        this.k = eVar;
        this.l = layoutParams;
        this.a = point2.x;
        this.b = point2.y;
        this.c = point.x;
        this.d = point.y;
        this.e = point3.x;
        this.f = point3.y;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.g, fVar.g) && Intrinsics.b(this.h, fVar.h) && Intrinsics.b(this.i, fVar.i) && Intrinsics.b(this.j, fVar.j) && Intrinsics.b(this.k, fVar.k) && Intrinsics.b(this.l, fVar.l);
    }

    public final int hashCode() {
        Rect rect = this.g;
        int iHashCode = (rect != null ? rect.hashCode() : 0) * 31;
        Point point = this.h;
        int iHashCode2 = (iHashCode + (point != null ? point.hashCode() : 0)) * 31;
        Point point2 = this.i;
        int iHashCode3 = (iHashCode2 + (point2 != null ? point2.hashCode() : 0)) * 31;
        Point point3 = this.j;
        int iHashCode4 = (iHashCode3 + (point3 != null ? point3.hashCode() : 0)) * 31;
        e eVar = this.k;
        int iHashCode5 = (iHashCode4 + (eVar != null ? eVar.hashCode() : 0)) * 31;
        WindowManager.LayoutParams layoutParams = this.l;
        return iHashCode5 + (layoutParams != null ? layoutParams.hashCode() : 0);
    }

    public final String toString() {
        return "Positions(displayFrame=" + this.g + ", arrowPoint=" + this.h + ", centerPoint=" + this.i + ", contentPoint=" + this.j + ", gravity=" + this.k + ", params=" + this.l + ")";
    }
}
