package app.cash.sqldelight.driver.android;

import android.text.SpannableStringBuilder;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;
import org.wordpress.aztec.formatting.n;

/* loaded from: classes.dex */
public final class g extends r implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(String str, i iVar, int i) {
        super(0);
        this.c = str;
        this.d = iVar;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new c((String) this.c, ((i) this.d).i(), this.b);
            default:
                ((n) this.c).u().insert(this.b, (SpannableStringBuilder) this.d);
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(n nVar, int i, SpannableStringBuilder spannableStringBuilder) {
        super(0);
        this.c = nVar;
        this.b = i;
        this.d = spannableStringBuilder;
    }
}
