package androidx.compose.material3;

import androidx.compose.material3.internal.C0659x;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.c4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0600c4 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ float c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0600c4(float f, boolean z, boolean z2) {
        super(1);
        this.a = z;
        this.b = z2;
        this.c = f;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0659x c0659x = (C0659x) obj;
        c0659x.a(EnumC0630h4.c, DefinitionKt.NO_Float_VALUE);
        boolean z = this.a;
        boolean z2 = this.b;
        float f = this.c;
        if (z) {
            c0659x.a(EnumC0630h4.a, z2 ? -f : f);
        }
        EnumC0630h4 enumC0630h4 = EnumC0630h4.b;
        if (!z2) {
            f = -f;
        }
        c0659x.a(enumC0630h4, f);
        return Unit.a;
    }
}
