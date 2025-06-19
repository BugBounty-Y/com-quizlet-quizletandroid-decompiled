package assistantMode.utils.classification;

import androidx.compose.ui.node.V;
import java.util.Locale;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.Regex;
import kotlin.u;

/* loaded from: classes.dex */
public final class c extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ V b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(V v, int i) {
        super(0);
        this.a = i;
        this.b = v;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                String lowerCase = ((String) this.b.d).toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                return lowerCase;
            case 1:
                return ((Regex) e.b.getValue()).g(9, (String) ((u) this.b.h).getValue());
            case 2:
                String lowerCase2 = ((String) this.b.b).toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
                return lowerCase2;
            default:
                return ((Regex) e.b.getValue()).g(9, (String) ((u) this.b.f).getValue());
        }
    }
}
