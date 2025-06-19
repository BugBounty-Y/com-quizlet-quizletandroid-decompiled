package androidx.compose.ui.text;

import android.graphics.RectF;
import androidx.camera.camera2.internal.s0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.paging.AbstractC1348x;
import androidx.paging.C1352z;
import androidx.paging.k1;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.util.ArrayList;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;

/* renamed from: androidx.compose.ui.text.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0981a extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0981a(Object obj, int i) {
        super(2);
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        boolean zH;
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                androidx.compose.ui.geometry.c cVarD = androidx.compose.ui.graphics.F.D((RectF) obj);
                androidx.compose.ui.geometry.c cVarD2 = androidx.compose.ui.graphics.F.D((RectF) obj2);
                switch (((s0) obj3).a) {
                    case 8:
                        zH = cVarD.h(cVarD2);
                        break;
                    default:
                        zH = cVarD2.a(cVarD.c());
                        break;
                }
                return Boolean.valueOf(zH);
            case 1:
                ((Number) obj2).intValue();
                ((androidx.compose.ui.window.q) obj3).Content((InterfaceC0806l) obj, C0776c.H(1));
                return Unit.a;
            case 2:
                ((Number) obj2).intValue();
                ((androidx.compose.ui.window.u) obj3).Content((InterfaceC0806l) obj, C0776c.H(1));
                return Unit.a;
            case 3:
                ((Number) obj2).intValue();
                AbstractC3336f.b((androidx.glance.p) obj3, (InterfaceC0806l) obj, 1);
                return Unit.a;
            case 4:
                C1352z prependHint = (C1352z) obj;
                C1352z appendHint = (C1352z) obj2;
                Intrinsics.checkNotNullParameter(prependHint, "prependHint");
                Intrinsics.checkNotNullParameter(appendHint, "appendHint");
                k1 k1Var = (k1) obj3;
                if (AbstractC1348x.d(k1Var, prependHint.a, androidx.paging.G.b)) {
                    prependHint.a = k1Var;
                    prependHint.b.h(k1Var);
                }
                if (AbstractC1348x.d(k1Var, appendHint.a, androidx.paging.G.c)) {
                    appendHint.a = k1Var;
                    appendHint.b.h(k1Var);
                }
                return Unit.a;
            case 5:
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it2, "it");
                return (kotlin.random.e) obj3;
            case 6:
                org.koin.core.scope.a single2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single2, "$this$single");
                Intrinsics.checkNotNullParameter(it3, "it");
                return (ExperimentConfiguration) obj3;
            case 7:
                String filename = (String) obj2;
                Intrinsics.checkNotNullParameter((String) obj, "<anonymous parameter 0>");
                Intrinsics.checkNotNullParameter(filename, "filename");
                com.mayakapps.kache.H h = (com.mayakapps.kache.H) obj3;
                Long l = (Long) h.a.y(okio.x.f(h.e, filename)).e;
                return Long.valueOf(l != null ? l.longValue() : 0L);
            case 8:
                String id = (String) obj;
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                Intrinsics.checkNotNullParameter(id, "id");
                com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = ((com.onetrust.otpublishers.headless.UI.fragment.s) obj3).S();
                dVarS.getClass();
                Intrinsics.checkNotNullParameter(id, "id");
                OTPublishersHeadlessSDK oTPublishersHeadlessSDK = dVarS.d;
                if (oTPublishersHeadlessSDK != null) {
                    oTPublishersHeadlessSDK.updateSDKConsentStatus(id, zBooleanValue);
                }
                ArrayList arrayList = dVarS.n;
                arrayList.add(id);
                String strC = dVarS.l.c(id);
                if (strC != null) {
                }
                dVarS.B();
                if (zBooleanValue) {
                    dVarS.D();
                } else {
                    dVarS.t.l(Boolean.FALSE);
                }
                return Unit.a;
            case 9:
                String answer = (String) obj;
                String test2 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer, "answer");
                Intrinsics.checkNotNullParameter(test2, "test");
                Pair pair = new Pair(answer, test2);
                for (Function2 function2 : (Function2[]) obj3) {
                    pair = (Pair) function2.invoke((String) pair.a, (String) pair.b);
                }
                return pair;
            default:
                ((Number) obj).intValue();
                ((Number) obj2).intValue();
                EnumC5145a enumC5145a = AztecText.q1;
                ((AztecText) obj3).getClass();
                return Boolean.TRUE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0981a(Object obj, int i, int i2) {
        super(2);
        this.a = i2;
        this.b = obj;
    }
}
