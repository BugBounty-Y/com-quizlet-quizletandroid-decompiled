package kotlin.jvm.internal;

import androidx.compose.animation.d0;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.List;
import kotlin.collections.CollectionsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class U implements kotlin.reflect.o {

    @NotNull
    public static final S d = new S(null);
    public final kotlin.reflect.d a;
    public final List b;
    public final int c;

    public U(kotlin.reflect.d classifier, List arguments, int i) {
        Intrinsics.checkNotNullParameter(classifier, "classifier");
        Intrinsics.checkNotNullParameter(arguments, "arguments");
        this.a = classifier;
        this.b = arguments;
        this.c = i;
    }

    @Override // kotlin.reflect.o
    public final List a() {
        return this.b;
    }

    @Override // kotlin.reflect.o
    public final boolean b() {
        return (this.c & 1) != 0;
    }

    public final String c(boolean z) {
        String name;
        kotlin.reflect.d dVar = this.a;
        kotlin.reflect.c cVar = dVar instanceof kotlin.reflect.c ? (kotlin.reflect.c) dVar : null;
        Class clsB = cVar != null ? kotlin.jvm.a.b(cVar) : null;
        if (clsB == null) {
            name = dVar.toString();
        } else if ((this.c & 4) != 0) {
            name = "kotlin.Nothing";
        } else if (clsB.isArray()) {
            name = clsB.equals(boolean[].class) ? "kotlin.BooleanArray" : clsB.equals(char[].class) ? "kotlin.CharArray" : clsB.equals(byte[].class) ? "kotlin.ByteArray" : clsB.equals(short[].class) ? "kotlin.ShortArray" : clsB.equals(int[].class) ? "kotlin.IntArray" : clsB.equals(float[].class) ? "kotlin.FloatArray" : clsB.equals(long[].class) ? "kotlin.LongArray" : clsB.equals(double[].class) ? "kotlin.DoubleArray" : "kotlin.Array";
        } else if (z && clsB.isPrimitive()) {
            Intrinsics.e(dVar, "null cannot be cast to non-null type kotlin.reflect.KClass<*>");
            name = kotlin.jvm.a.c((kotlin.reflect.c) dVar).getName();
        } else {
            name = clsB.getName();
        }
        return android.support.v4.media.session.a.l(name, this.b.isEmpty() ? "" : CollectionsKt.S(this.b, ", ", SimpleComparison.LESS_THAN_OPERATION, SimpleComparison.GREATER_THAN_OPERATION, new T(this), 24), b() ? "?" : "");
    }

    @Override // kotlin.reflect.o
    public final kotlin.reflect.d d() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof U)) {
            return false;
        }
        U u = (U) obj;
        return Intrinsics.b(this.a, u.a) && Intrinsics.b(this.b, u.b) && this.c == u.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.f(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return c(false) + " (Kotlin reflection is not available)";
    }
}
