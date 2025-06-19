package androidx.compose.ui.graphics;

import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.RectF;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.graphics.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0850j implements O {
    public final Path a;
    public RectF b;
    public float[] c;
    public Matrix d;

    public C0850j(Path path) {
        this.a = path;
    }

    public final androidx.compose.ui.geometry.c c() {
        if (this.b == null) {
            this.b = new RectF();
        }
        RectF rectF = this.b;
        Intrinsics.d(rectF);
        this.a.computeBounds(rectF, true);
        return new androidx.compose.ui.geometry.c(rectF.left, rectF.top, rectF.right, rectF.bottom);
    }

    public final boolean d(O o, O o2, int i) {
        Path.Op op = i == 0 ? Path.Op.DIFFERENCE : i == 1 ? Path.Op.INTERSECT : i == 4 ? Path.Op.REVERSE_DIFFERENCE : i == 2 ? Path.Op.UNION : Path.Op.XOR;
        if (!(o instanceof C0850j)) {
            throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
        }
        Path path = ((C0850j) o).a;
        if (o2 instanceof C0850j) {
            return this.a.op(path, ((C0850j) o2).a, op);
        }
        throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
    }

    public final void e() {
        this.a.reset();
    }

    public final void f(int i) {
        this.a.setFillType(i == 1 ? Path.FillType.EVEN_ODD : Path.FillType.WINDING);
    }

    public final void g(long j) {
        Matrix matrix = this.d;
        if (matrix == null) {
            this.d = new Matrix();
        } else {
            matrix.reset();
        }
        Matrix matrix2 = this.d;
        Intrinsics.d(matrix2);
        matrix2.setTranslate(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
        Matrix matrix3 = this.d;
        Intrinsics.d(matrix3);
        this.a.transform(matrix3);
    }
}
