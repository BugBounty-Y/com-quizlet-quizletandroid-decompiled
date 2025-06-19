package assistantMode.utils.classification;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;
import kotlin.text.Regex;

/* loaded from: classes.dex */
public final class d extends r implements Function0 {
    public static final d b = new d(0, 0);
    public static final d c = new d(0, 1);
    public static final d d = new d(0, 2);
    public static final d e = new d(0, 3);
    public static final d f = new d(0, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new Regex("[\\s,]+");
            case 1:
                return new Regex("[\\s, .]+");
            case 2:
                return new Regex("\\s+");
            case 3:
                return new Regex("\\.|,");
            default:
                return new Regex("\\s+");
        }
    }
}
