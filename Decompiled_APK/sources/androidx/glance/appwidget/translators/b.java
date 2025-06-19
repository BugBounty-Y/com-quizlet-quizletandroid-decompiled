package androidx.glance.appwidget.translators;

import androidx.glance.layout.m;
import androidx.glance.layout.t;
import androidx.glance.o;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class b extends r implements Function2 {
    public static final b b = new b(2, 0);
    public static final b c = new b(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                o oVar = (o) obj2;
                return oVar instanceof t ? oVar : obj;
            default:
                o oVar2 = (o) obj2;
                return oVar2 instanceof m ? oVar2 : obj;
        }
    }
}
