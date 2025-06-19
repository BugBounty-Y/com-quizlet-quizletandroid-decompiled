package androidx.compose.ui.platform;

import android.graphics.Matrix;
import androidx.lifecycle.C1247h;
import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.y0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0978y0 {
    public boolean a;
    public boolean b;
    public boolean c;
    public final Object d;
    public Object e;
    public Object f;
    public Object g;
    public Cloneable h;

    public C0978y0(androidx.savedstate.f owner, C1247h onAttach) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(onAttach, "onAttach");
        this.d = owner;
        this.e = onAttach;
        this.f = new com.google.android.gms.internal.mlkit_common.u(5);
        this.g = new LinkedHashMap();
        this.c = true;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [float[], java.lang.Cloneable] */
    public float[] a(Object obj) {
        float[] fArr = (float[]) this.h;
        float[] fArr2 = fArr;
        if (fArr == null) {
            ?? A = androidx.compose.ui.graphics.J.a();
            this.h = A;
            fArr2 = A;
        }
        if (this.b) {
            this.c = N.x(b(obj), fArr2);
            this.b = false;
        }
        if (this.c) {
            return fArr2;
        }
        return null;
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    public float[] b(Object obj) {
        float[] fArrA = (float[]) this.g;
        if (fArrA == null) {
            fArrA = androidx.compose.ui.graphics.J.a();
            this.g = fArrA;
        }
        if (!this.a) {
            return fArrA;
        }
        Matrix matrix = (Matrix) this.e;
        if (matrix == null) {
            matrix = new Matrix();
            this.e = matrix;
        }
        ((kotlin.jvm.internal.r) this.d).invoke(obj, matrix);
        Matrix matrix2 = (Matrix) this.f;
        if (matrix2 == null || !matrix.equals(matrix2)) {
            androidx.compose.ui.graphics.F.u(matrix, fArrA);
            this.e = matrix2;
            this.f = matrix;
        }
        this.a = false;
        return fArrA;
    }

    public void c() {
        this.a = true;
        this.b = true;
    }

    public void d() {
        androidx.savedstate.f fVar = (androidx.savedstate.f) this.d;
        if (((androidx.lifecycle.L) fVar.getLifecycle()).d != androidx.lifecycle.B.b) {
            throw new IllegalStateException("Restarter must be created only during owner's initialization stage");
        }
        if (this.a) {
            throw new IllegalStateException("SavedStateRegistry was already attached.");
        }
        ((C1247h) this.e).invoke();
        fVar.getLifecycle().a(new X0(this, 2));
        this.a = true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C0978y0(Function2 function2) {
        this.d = (kotlin.jvm.internal.r) function2;
        this.a = true;
        this.b = true;
        this.c = true;
    }
}
