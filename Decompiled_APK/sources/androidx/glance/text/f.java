package androidx.glance.text;

import androidx.compose.runtime.InterfaceC0806l;
import androidx.glance.p;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class f extends r implements Function2 {
    public final /* synthetic */ String a;
    public final /* synthetic */ p b;
    public final /* synthetic */ g c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(String str, p pVar, g gVar, int i, int i2, int i3) {
        super(2);
        this.a = str;
        this.b = pVar;
        this.c = gVar;
        this.d = i;
        this.e = i2;
        this.f = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int i = this.e | 1;
        p pVar = this.b;
        AbstractC3401v1.a(this.a, pVar, this.c, this.d, (InterfaceC0806l) obj, i, this.f);
        return Unit.a;
    }
}
