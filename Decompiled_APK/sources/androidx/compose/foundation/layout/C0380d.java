package androidx.compose.foundation.layout;

import android.view.View;
import androidx.compose.animation.C0278e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.layout.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0380d implements InterfaceC0388h {
    public final /* synthetic */ int a;

    public /* synthetic */ C0380d(int i) {
        this.a = i;
    }

    public static final C0378c b(int i, String str) {
        WeakHashMap weakHashMap = S0.w;
        return new C0378c(i, str);
    }

    public static final P0 d(int i, String str) {
        WeakHashMap weakHashMap = S0.w;
        return new P0(new C0408r0(0, 0, 0, 0), str);
    }

    public static S0 e(InterfaceC0806l interfaceC0806l) {
        S0 s0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
        WeakHashMap weakHashMap = S0.w;
        synchronized (weakHashMap) {
            try {
                Object s02 = weakHashMap.get(view);
                if (s02 == null) {
                    s02 = new S0(view);
                    weakHashMap.put(view, s02);
                }
                s0 = (S0) s02;
            } catch (Throwable th) {
                throw th;
            }
        }
        boolean zH = c0814p.h(s0) | c0814p.h(view);
        Object objI = c0814p.I();
        if (zH || objI == C0804k.a) {
            objI = new C0278e(15, s0, view);
            c0814p.i0(objI);
        }
        C0776c.d(s0, (Function1) objI, c0814p);
        return s0;
    }

    @Override // androidx.compose.foundation.layout.InterfaceC0388h
    public void c(androidx.compose.ui.unit.b bVar, int i, int[] iArr, androidx.compose.ui.unit.k kVar, int[] iArr2) {
        switch (this.a) {
            case 0:
                AbstractC0398m.b(iArr, iArr2, false);
                break;
            case 1:
                AbstractC0398m.c(i, iArr, iArr2, false);
                break;
            case 2:
                if (kVar != androidx.compose.ui.unit.k.a) {
                    AbstractC0398m.b(iArr, iArr2, true);
                    break;
                } else {
                    AbstractC0398m.c(i, iArr, iArr2, false);
                    break;
                }
            default:
                if (kVar != androidx.compose.ui.unit.k.a) {
                    AbstractC0398m.c(i, iArr, iArr2, true);
                    break;
                } else {
                    AbstractC0398m.b(iArr, iArr2, false);
                    break;
                }
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "AbsoluteArrangement#Left";
            case 1:
                return "AbsoluteArrangement#Right";
            case 2:
                return "Arrangement#End";
            case 3:
                return "Arrangement#Start";
            default:
                return super.toString();
        }
    }
}
