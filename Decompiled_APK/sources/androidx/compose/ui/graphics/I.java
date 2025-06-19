package androidx.compose.ui.graphics;

import android.graphics.LinearGradient;
import android.graphics.Shader;
import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I extends T {
    public final List c;
    public final ArrayList d;
    public final long e;
    public final long f;

    public I(List list, ArrayList arrayList, long j, long j2) {
        this.c = list;
        this.d = arrayList;
        this.e = j;
        this.f = j2;
    }

    @Override // androidx.compose.ui.graphics.T
    public final Shader b(long j) {
        long j2 = this.e;
        float fD = androidx.compose.ui.geometry.b.d(j2) == Float.POSITIVE_INFINITY ? androidx.compose.ui.geometry.e.d(j) : androidx.compose.ui.geometry.b.d(j2);
        float fB = androidx.compose.ui.geometry.b.e(j2) == Float.POSITIVE_INFINITY ? androidx.compose.ui.geometry.e.b(j) : androidx.compose.ui.geometry.b.e(j2);
        long j3 = this.f;
        float fD2 = androidx.compose.ui.geometry.b.d(j3) == Float.POSITIVE_INFINITY ? androidx.compose.ui.geometry.e.d(j) : androidx.compose.ui.geometry.b.d(j3);
        float fB2 = androidx.compose.ui.geometry.b.e(j3) == Float.POSITIVE_INFINITY ? androidx.compose.ui.geometry.e.b(j) : androidx.compose.ui.geometry.b.e(j3);
        long jC = Q4.c(fD, fB);
        long jC2 = Q4.c(fD2, fB2);
        ArrayList arrayList = this.d;
        List list = this.c;
        if (arrayList == null) {
            if (list.size() < 2) {
                throw new IllegalArgumentException("colors must have length of at least 2 if colorStops is omitted.");
            }
        } else if (list.size() != arrayList.size()) {
            throw new IllegalArgumentException("colors and colorStops arguments must have equal length.");
        }
        float fD3 = androidx.compose.ui.geometry.b.d(jC);
        float fE = androidx.compose.ui.geometry.b.e(jC);
        float fD4 = androidx.compose.ui.geometry.b.d(jC2);
        float fE2 = androidx.compose.ui.geometry.b.e(jC2);
        int size = list.size();
        int[] iArr = new int[size];
        for (int i = 0; i < size; i++) {
            iArr[i] = F.A(((C0861v) list.get(i)).a);
        }
        return new LinearGradient(fD3, fE, fD4, fE2, iArr, arrayList != null ? CollectionsKt.t0(arrayList) : null, F.z(0));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return Intrinsics.b(this.c, i.c) && Intrinsics.b(this.d, i.d) && androidx.compose.ui.geometry.b.b(this.e, i.e) && androidx.compose.ui.geometry.b.b(this.f, i.f);
    }

    public final int hashCode() {
        int iHashCode = this.c.hashCode() * 31;
        ArrayList arrayList = this.d;
        return Integer.hashCode(0) + d0.d(d0.d((iHashCode + (arrayList != null ? arrayList.hashCode() : 0)) * 31, 31, this.e), 31, this.f);
    }

    public final String toString() {
        String str;
        long j = this.e;
        String str2 = "";
        if (Q4.g(j)) {
            str = "start=" + ((Object) androidx.compose.ui.geometry.b.j(j)) + ", ";
        } else {
            str = "";
        }
        long j2 = this.f;
        if (Q4.g(j2)) {
            str2 = "end=" + ((Object) androidx.compose.ui.geometry.b.j(j2)) + ", ";
        }
        return "LinearGradient(colors=" + this.c + ", stops=" + this.d + ", " + str + str2 + "tileMode=" + ((Object) "Clamp") + ')';
    }
}
