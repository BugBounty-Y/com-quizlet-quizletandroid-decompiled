package kotlin.jvm;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.glance.appwidget.action.g;
import androidx.glance.layout.c;
import androidx.glance.n;
import androidx.glance.p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3207m7;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.z;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InterfaceC4948g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.appcompat.view.a linkProvider, n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(linkProvider, "linkProvider");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2018765626);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(linkProvider) : c0814p.h(linkProvider) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if (((i2 | 48) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = n.a;
            p pVarB = AbstractC3207m7.b(AbstractC3180j7.b(AbstractC3332e.d(nVar), new androidx.glance.a(R.drawable.bg_widget)), g.a(linkProvider.b()));
            c0814p.X(1550280300);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(21);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            M7.a(AbstractC3340g.c(pVarB, (Function1) objI), c.e, com.quizlet.quizletandroid.ui.widgets.g.a, c0814p, 384, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.widgets.p(linkProvider, nVar, i, 0);
        }
    }

    public static final Class b(kotlin.reflect.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Class clsC = ((InterfaceC4948g) cVar).c();
        Intrinsics.e(clsC, "null cannot be cast to non-null type java.lang.Class<T of kotlin.jvm.JvmClassMappingKt.<get-java>>");
        return clsC;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    public static final Class c(kotlin.reflect.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Class clsC = ((InterfaceC4948g) cVar).c();
        if (clsC.isPrimitive()) {
            String name = clsC.getName();
            switch (name.hashCode()) {
                case -1325958191:
                    if (name.equals("double")) {
                        return Double.class;
                    }
                    break;
                case 104431:
                    if (name.equals("int")) {
                        return Integer.class;
                    }
                    break;
                case 3039496:
                    if (name.equals("byte")) {
                        return Byte.class;
                    }
                    break;
                case 3052374:
                    if (name.equals("char")) {
                        return Character.class;
                    }
                    break;
                case 3327612:
                    if (name.equals("long")) {
                        return Long.class;
                    }
                    break;
                case 3625364:
                    if (name.equals("void")) {
                        return Void.class;
                    }
                    break;
                case 64711720:
                    if (name.equals("boolean")) {
                        return Boolean.class;
                    }
                    break;
                case 97526364:
                    if (name.equals("float")) {
                        return Float.class;
                    }
                    break;
                case 109413500:
                    if (name.equals("short")) {
                        return Short.class;
                    }
                    break;
            }
        }
        return clsC;
    }
}
