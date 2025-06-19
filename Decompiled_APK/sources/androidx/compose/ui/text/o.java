package androidx.compose.ui.text;

import android.graphics.Matrix;
import android.graphics.Shader;
import android.text.Layout;
import androidx.camera.camera2.internal.s0;
import androidx.compose.foundation.C0552u;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.T;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.graphics.X;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class o {
    public final com.quizlet.remote.model.notes.e a;
    public final int b;
    public final boolean c;
    public final float d;
    public final float e;
    public final int f;
    public final ArrayList g;
    public final ArrayList h;

    /* JADX WARN: Type inference failed for: r7v1, types: [java.lang.Object, java.util.List] */
    public o(com.quizlet.remote.model.notes.e eVar, long j, int i, boolean z) {
        boolean z2;
        int iG;
        this.a = eVar;
        this.b = i;
        if (androidx.compose.ui.unit.a.j(j) != 0 || androidx.compose.ui.unit.a.i(j) != 0) {
            throw new IllegalArgumentException("Setting Constraints.minWidth and Constraints.minHeight is not supported, these should be the default zero values instead.");
        }
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = (ArrayList) eVar.f;
        int size = arrayList2.size();
        int i2 = 0;
        int i3 = 0;
        float f = DefinitionKt.NO_Float_VALUE;
        while (i2 < size) {
            r rVar = (r) arrayList2.get(i2);
            androidx.compose.ui.text.platform.c cVar = rVar.a;
            int iH = androidx.compose.ui.unit.a.h(j);
            if (androidx.compose.ui.unit.a.c(j)) {
                iG = androidx.compose.ui.unit.a.g(j) - ((int) Math.ceil(f));
                if (iG < 0) {
                    iG = 0;
                }
            } else {
                iG = androidx.compose.ui.unit.a.g(j);
            }
            C0982b c0982b = new C0982b(cVar, this.b - i3, z, L5.b(iH, iG, 5));
            float fB = c0982b.b() + f;
            androidx.compose.ui.text.android.x xVar = c0982b.d;
            int i4 = i3 + xVar.f;
            arrayList.add(new q(c0982b, rVar.b, rVar.c, i3, i4, f, fB));
            if (xVar.c || (i4 == this.b && i2 != kotlin.collections.B.i((ArrayList) this.a.f))) {
                z2 = true;
                i3 = i4;
                f = fB;
                break;
            } else {
                i2++;
                i3 = i4;
                f = fB;
            }
        }
        z2 = false;
        this.e = f;
        this.f = i3;
        this.c = z2;
        this.h = arrayList;
        this.d = androidx.compose.ui.unit.a.h(j);
        ArrayList arrayList3 = new ArrayList(arrayList.size());
        int size2 = arrayList.size();
        for (int i5 = 0; i5 < size2; i5++) {
            q qVar = (q) arrayList.get(i5);
            ?? r7 = qVar.a.f;
            ArrayList arrayList4 = new ArrayList(r7.size());
            int size3 = r7.size();
            for (int i6 = 0; i6 < size3; i6++) {
                androidx.compose.ui.geometry.c cVar2 = (androidx.compose.ui.geometry.c) r7.get(i6);
                arrayList4.add(cVar2 != null ? cVar2.j(Q4.c(DefinitionKt.NO_Float_VALUE, qVar.f)) : null);
            }
            kotlin.collections.G.u(arrayList3, arrayList4);
        }
        if (arrayList3.size() < ((List) this.a.c).size()) {
            int size4 = ((List) this.a.c).size() - arrayList3.size();
            ArrayList arrayList5 = new ArrayList(size4);
            for (int i7 = 0; i7 < size4; i7++) {
                arrayList5.add(null);
            }
            arrayList3 = CollectionsKt.c0(arrayList3, arrayList5);
        }
        this.g = arrayList3;
    }

    public static void g(o oVar, InterfaceC0858s interfaceC0858s, long j, U u, androidx.compose.ui.text.style.j jVar, androidx.compose.ui.graphics.drawscope.e eVar) {
        interfaceC0858s.e();
        ArrayList arrayList = oVar.h;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            q qVar = (q) arrayList.get(i);
            qVar.a.f(interfaceC0858s, j, u, jVar, eVar);
            interfaceC0858s.p(DefinitionKt.NO_Float_VALUE, qVar.a.b());
        }
        interfaceC0858s.q();
    }

    public static void h(o oVar, InterfaceC0858s interfaceC0858s, AbstractC0857q abstractC0857q, float f, U u, androidx.compose.ui.text.style.j jVar, androidx.compose.ui.graphics.drawscope.e eVar) {
        interfaceC0858s.e();
        ArrayList arrayList = oVar.h;
        if (arrayList.size() <= 1 || (abstractC0857q instanceof X)) {
            androidx.compose.ui.text.platform.i.a(oVar, interfaceC0858s, abstractC0857q, f, u, jVar, eVar);
        } else if (abstractC0857q instanceof T) {
            int size = arrayList.size();
            float fMax = 0.0f;
            float fB = 0.0f;
            for (int i = 0; i < size; i++) {
                q qVar = (q) arrayList.get(i);
                fB += qVar.a.b();
                fMax = Math.max(fMax, qVar.a.d());
            }
            Shader shaderB = ((T) abstractC0857q).b(T4.a(fMax, fB));
            Matrix matrix = new Matrix();
            shaderB.getLocalMatrix(matrix);
            int size2 = arrayList.size();
            for (int i2 = 0; i2 < size2; i2++) {
                q qVar2 = (q) arrayList.get(i2);
                qVar2.a.g(interfaceC0858s, new androidx.compose.ui.graphics.r(shaderB), f, u, jVar, eVar);
                C0982b c0982b = qVar2.a;
                interfaceC0858s.p(DefinitionKt.NO_Float_VALUE, c0982b.b());
                matrix.setTranslate(DefinitionKt.NO_Float_VALUE, -c0982b.b());
                shaderB.setLocalMatrix(matrix);
            }
        }
        interfaceC0858s.q();
    }

    public final void a(long j, float[] fArr) {
        i(K.e(j));
        j(K.d(j));
        kotlin.jvm.internal.H h = new kotlin.jvm.internal.H();
        h.a = 0;
        AbstractC3169i5.e(this.h, j, new C0552u(j, fArr, h, new kotlin.jvm.internal.G()));
    }

    public final float b(int i) {
        k(i);
        ArrayList arrayList = this.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.c(i, arrayList));
        C0982b c0982b = qVar.a;
        return c0982b.d.e(i - qVar.d) + qVar.f;
    }

    public final int c(float f) {
        ArrayList arrayList = this.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.d(arrayList, f));
        int i = qVar.c - qVar.b;
        int i2 = qVar.d;
        if (i == 0) {
            return i2;
        }
        float f2 = f - qVar.f;
        androidx.compose.ui.text.android.x xVar = qVar.a.d;
        return xVar.e.getLineForVertical(((int) f2) - xVar.g) + i2;
    }

    public final float d(int i) {
        k(i);
        ArrayList arrayList = this.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.c(i, arrayList));
        C0982b c0982b = qVar.a;
        return c0982b.d.g(i - qVar.d) + qVar.f;
    }

    public final int e(long j) {
        ArrayList arrayList = this.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.d(arrayList, androidx.compose.ui.geometry.b.e(j)));
        int i = qVar.c;
        int i2 = qVar.b;
        if (i - i2 == 0) {
            return i2;
        }
        long jC = Q4.c(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j) - qVar.f);
        C0982b c0982b = qVar.a;
        int iE = (int) androidx.compose.ui.geometry.b.e(jC);
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        int i3 = iE - xVar.g;
        Layout layout = xVar.e;
        int lineForVertical = layout.getLineForVertical(i3);
        return layout.getOffsetForHorizontal(lineForVertical, (xVar.b(lineForVertical) * (-1)) + androidx.compose.ui.geometry.b.d(jC)) + i2;
    }

    public final long f(androidx.compose.ui.geometry.c cVar, int i, s0 s0Var) {
        long jA;
        long j;
        ArrayList arrayList = this.h;
        int iD = AbstractC3169i5.d(arrayList, cVar.b);
        float f = ((q) arrayList.get(iD)).g;
        float f2 = cVar.d;
        if (f >= f2 || iD == kotlin.collections.B.i(arrayList)) {
            q qVar = (q) arrayList.get(iD);
            return qVar.a(qVar.a.c(cVar.j(Q4.c(DefinitionKt.NO_Float_VALUE, -qVar.f)), i, s0Var), true);
        }
        int iD2 = AbstractC3169i5.d(arrayList, f2);
        long jA2 = K.b;
        while (true) {
            jA = K.b;
            if (!K.a(jA2, jA) || iD > iD2) {
                break;
            }
            q qVar2 = (q) arrayList.get(iD);
            jA2 = qVar2.a(qVar2.a.c(cVar.j(Q4.c(DefinitionKt.NO_Float_VALUE, -qVar2.f)), i, s0Var), true);
            iD++;
        }
        if (K.a(jA2, jA)) {
            return jA;
        }
        while (true) {
            j = K.b;
            if (!K.a(jA, j) || iD > iD2) {
                break;
            }
            q qVar3 = (q) arrayList.get(iD2);
            jA = qVar3.a(qVar3.a.c(cVar.j(Q4.c(DefinitionKt.NO_Float_VALUE, -qVar3.f)), i, s0Var), true);
            iD2--;
        }
        return K.a(jA, j) ? jA2 : AbstractC3205m5.c((int) (jA2 >> 32), (int) (4294967295L & jA));
    }

    public final void i(int i) {
        com.quizlet.remote.model.notes.e eVar = this.a;
        if (i < 0 || i >= ((C0995g) eVar.b).a.length()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "offset(", ") is out of bounds [0, ");
            sbV.append(((C0995g) eVar.b).a.length());
            sbV.append(')');
            throw new IllegalArgumentException(sbV.toString().toString());
        }
    }

    public final void j(int i) {
        com.quizlet.remote.model.notes.e eVar = this.a;
        if (i < 0 || i > ((C0995g) eVar.b).a.length()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "offset(", ") is out of bounds [0, ");
            sbV.append(((C0995g) eVar.b).a.length());
            sbV.append(']');
            throw new IllegalArgumentException(sbV.toString().toString());
        }
    }

    public final void k(int i) {
        int i2 = this.f;
        if (i < 0 || i >= i2) {
            throw new IllegalArgumentException(("lineIndex(" + i + ") is out of bounds [0, " + i2 + ')').toString());
        }
    }
}
