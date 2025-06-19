package androidx.compose.ui.unit.fontscaling;

import androidx.collection.W;
import androidx.collection.r;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;

/* loaded from: classes.dex */
public abstract class b {
    public static final float[] a = {8.0f, 10.0f, 12.0f, 14.0f, 18.0f, 20.0f, 24.0f, 30.0f, 100.0f};
    public static volatile W b = new W(0);
    public static final Object[] c;

    static {
        Object[] objArr = new Object[0];
        c = objArr;
        synchronized (objArr) {
            b.f((int) 115.0f, new c(new float[]{8.0f, 10.0f, 12.0f, 14.0f, 18.0f, 20.0f, 24.0f, 30.0f, 100.0f}, new float[]{9.2f, 11.5f, 13.8f, 16.4f, 19.8f, 21.8f, 25.2f, 30.0f, 100.0f}));
            b.f((int) 130.0f, new c(new float[]{8.0f, 10.0f, 12.0f, 14.0f, 18.0f, 20.0f, 24.0f, 30.0f, 100.0f}, new float[]{10.4f, 13.0f, 15.6f, 18.8f, 21.6f, 23.6f, 26.4f, 30.0f, 100.0f}));
            b.f((int) 150.0f, new c(new float[]{8.0f, 10.0f, 12.0f, 14.0f, 18.0f, 20.0f, 24.0f, 30.0f, 100.0f}, new float[]{12.0f, 15.0f, 18.0f, 22.0f, 24.0f, 26.0f, 28.0f, 30.0f, 100.0f}));
            b.f((int) 180.0f, new c(new float[]{8.0f, 10.0f, 12.0f, 14.0f, 18.0f, 20.0f, 24.0f, 30.0f, 100.0f}, new float[]{14.4f, 18.0f, 21.6f, 24.4f, 27.6f, 30.8f, 32.8f, 34.8f, 100.0f}));
            b.f((int) 200.0f, new c(new float[]{8.0f, 10.0f, 12.0f, 14.0f, 18.0f, 20.0f, 24.0f, 30.0f, 100.0f}, new float[]{16.0f, 20.0f, 24.0f, 26.0f, 30.0f, 34.0f, 36.0f, 38.0f, 100.0f}));
            Unit unit = Unit.a;
        }
        if ((b.e(0) / 100.0f) - 0.01f <= 1.03f) {
            throw new IllegalStateException("You should only apply non-linear scaling to font scales > 1");
        }
    }

    public static a a(float f) {
        float fE;
        a cVar;
        if (f < 1.03f) {
            return null;
        }
        int i = (int) (f * 100.0f);
        a aVar = (a) b.d(i);
        if (aVar != null) {
            return aVar;
        }
        W w = b;
        if (w.a) {
            r.a(w);
        }
        int iA = androidx.collection.internal.a.a(w.d, i, w.b);
        if (iA >= 0) {
            return (a) b.h(iA);
        }
        int i2 = -(iA + 1);
        int i3 = i2 - 1;
        if (i2 >= b.g()) {
            c cVar2 = new c(new float[]{1.0f}, new float[]{f});
            b(f, cVar2);
            return cVar2;
        }
        float[] fArr = a;
        if (i3 < 0) {
            cVar = new c(fArr, fArr);
            fE = 1.0f;
        } else {
            fE = b.e(i3) / 100.0f;
            cVar = (a) b.h(i3);
        }
        float fE2 = b.e(i2) / 100.0f;
        float fMax = (Math.max(DefinitionKt.NO_Float_VALUE, Math.min(1.0f, fE == fE2 ? 0.0f : (f - fE) / (fE2 - fE))) * 1.0f) + DefinitionKt.NO_Float_VALUE;
        a aVar2 = (a) b.h(i2);
        float[] fArr2 = new float[9];
        for (int i4 = 0; i4 < 9; i4++) {
            float f2 = fArr[i4];
            float fB = cVar.b(f2);
            fArr2[i4] = ((aVar2.b(f2) - fB) * fMax) + fB;
        }
        c cVar3 = new c(fArr, fArr2);
        b(f, cVar3);
        return cVar3;
    }

    public static void b(float f, c cVar) {
        synchronized (c) {
            W wClone = b.clone();
            wClone.f((int) (f * 100.0f), cVar);
            b = wClone;
            Unit unit = Unit.a;
        }
    }
}
