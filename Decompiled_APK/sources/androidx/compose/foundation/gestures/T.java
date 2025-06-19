package androidx.compose.foundation.gestures;

import android.content.res.Configuration;
import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.text.selection.C0536q;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ T(InterfaceC0773a0 interfaceC0773a0, int i) {
        super(1);
        this.a = i;
        this.b = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        InterfaceC0773a0 interfaceC0773a0 = this.b;
        switch (this.a) {
            case 0:
                ((Function1) interfaceC0773a0.getValue()).invoke(Float.valueOf(((Number) obj).floatValue()));
                break;
            case 1:
                break;
            case 2:
                androidx.compose.foundation.text.modifiers.k kVar = (androidx.compose.foundation.text.modifiers.k) obj;
                interfaceC0773a0.setValue(kVar.c ? kVar.b : kVar.a);
                break;
            case 3:
                List list = (List) obj;
                if (interfaceC0773a0 != null) {
                    interfaceC0773a0.setValue(list);
                }
                break;
            case 4:
                interfaceC0773a0.setValue((androidx.compose.ui.text.H) obj);
                break;
            case 5:
                ((Function1) interfaceC0773a0.getValue()).invoke(new androidx.compose.ui.geometry.b(((androidx.compose.ui.geometry.b) obj).a));
                break;
            case 6:
                interfaceC0773a0.setValue((C0536q) obj);
                break;
            case 7:
                androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
                if (!StringsKt.O((CharSequence) interfaceC0773a0.getValue())) {
                    String str = (String) interfaceC0773a0.getValue();
                    kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                    ((androidx.compose.ui.semantics.k) vVar).b(androidx.compose.ui.semantics.r.D, str);
                }
                break;
            case 8:
                androidx.compose.ui.node.G g = (androidx.compose.ui.node.G) obj;
                g.b();
                float fC0 = g.c0(((C0555x) interfaceC0773a0.getValue()).a);
                androidx.compose.ui.graphics.drawscope.b bVar = g.a;
                float fB = androidx.compose.ui.geometry.e.b(bVar.g()) - (fC0 / 2);
                androidx.compose.ui.graphics.drawscope.d.Y(g, ((C0555x) interfaceC0773a0.getValue()).b, Q4.c(DefinitionKt.NO_Float_VALUE, fB), Q4.c(androidx.compose.ui.geometry.e.d(bVar.g()), fB), fC0, DefinitionKt.NO_Float_VALUE, 496);
                break;
            default:
                Configuration configuration = new Configuration((Configuration) obj);
                androidx.compose.runtime.B b = AndroidCompositionLocals_androidKt.a;
                interfaceC0773a0.setValue(configuration);
                break;
        }
        return Unit.a;
    }
}
